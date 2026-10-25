#include "../src/gui/BatchCreatorWidget.h"
#include "../src/gui/CanonicalBenchmarkSelection.h"
#include "../src/gui/CreatorRowWidget.h"

#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTemporaryDir>

#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/BatchInputDocumentBuilder.h>
#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace cryptobench::tests {
namespace {

using namespace core;
using namespace gui;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void selectData(QComboBox* comboBox, int data)
{
    const int index = comboBox->findData(data);
    require(index >= 0, "canonical selection was not present in the control");
    comboBox->setCurrentIndex(index);
}

void requireConfigsEqual(const BenchmarkConfig& actual, const BenchmarkConfig& expected)
{
    require(actual.profile == expected.profile && actual.operation == expected.operation
                && actual.iterationsPerRun == expected.iterationsPerRun
                && actual.runs == expected.runs
                && actual.parameters.index() == expected.parameters.index(),
            "Creator row changed a canonical configuration field");
    if (std::holds_alternative<SignatureConfig>(actual.parameters)) {
        const auto& left = std::get<SignatureConfig>(actual.parameters).input;
        const auto& right = std::get<SignatureConfig>(expected.parameters).input;
        require(left.index() == right.index(), "Creator row changed signature input mode");
        if (std::holds_alternative<MessageInput>(left)) {
            require(std::get<MessageInput>(left).messageSize
                        == std::get<MessageInput>(right).messageSize,
                    "Creator row changed message workload size");
        }
    } else if (std::holds_alternative<AeadConfig>(actual.parameters)) {
        require(std::get<AeadConfig>(actual.parameters).plaintextSize
                    == std::get<AeadConfig>(expected.parameters).plaintextSize,
                "Creator row changed AEAD workload size");
    } else if (std::holds_alternative<HashConfig>(actual.parameters)) {
        require(std::get<HashConfig>(actual.parameters).inputSize
                    == std::get<HashConfig>(expected.parameters).inputSize,
                "Creator row changed Hash/XOF workload size");
    }
}

void configureHashRow(CreatorRowWidget* row, int inputSize, int iterations, int runs)
{
    selectData(row->categoryComboBox(), static_cast<int>(PrimitiveCategory::HashXof));
    selectData(row->profileComboBox(), static_cast<int>(AlgorithmProfileId::Sha256));
    selectData(row->operationComboBox(), static_cast<int>(BenchmarkOperation::Hash));
    row->workloadSizeSpinBox()->setValue(inputSize);
    row->iterationsSpinBox()->setValue(iterations);
    row->runsSpinBox()->setValue(runs);
}

void testRegistryDrivenSelectionCoverage()
{
    const auto categories = canonicalCategories();
    require(categories.size() == 4, "category count changed");
    const std::array expectedCategories{
        PrimitiveCategory::Signature,
        PrimitiveCategory::KeyEstablishment,
        PrimitiveCategory::Aead,
        PrimitiveCategory::HashXof
    };
    for (std::size_t index = 0; index < categories.size(); ++index) {
        require(categories[index].category == expectedCategories[index],
                "canonical category order changed");
    }

    const auto profiles = AlgorithmRegistry::all();
    require(profiles.size() == 72, "registry profile count changed");
    std::size_t profileCount = 0;
    std::size_t operationPairCount = 0;
    std::size_t inputModeCaseCount = 0;
    CreatorRowWidget row(defaultCreatorRowState());
    for (const auto& profile : profiles) {
        ++profileCount;
        const auto filteredProfiles = profilesForCategory(profile.category);
        require(std::find(filteredProfiles.begin(), filteredProfiles.end(), &profile)
                    != filteredProfiles.end(),
                "category filtering omitted a canonical profile");

        const auto operations = operationsForProfile(profile.id);
        for (const auto operation : operations) {
            ++operationPairCount;
            require(profile.operations.contains(operation),
                    "selection helper returned an unsupported operation");

            const auto appendCase = [&](std::optional<SignatureInputMode> mode) {
                BenchmarkSelection selection{
                    profile.category, profile.id, operation, mode, 64, 7, 3};
                selectData(row.categoryComboBox(), static_cast<int>(profile.category));
                selectData(row.profileComboBox(), static_cast<int>(profile.id));
                selectData(row.operationComboBox(), static_cast<int>(operation));
                if (mode.has_value()) {
                    selectData(row.signatureInputModeComboBox(), static_cast<int>(*mode));
                }
                row.workloadSizeSpinBox()->setValue(64);
                row.iterationsSpinBox()->setValue(7);
                row.runsSpinBox()->setValue(3);

                const auto expected = benchmarkConfigFromSelection(selection);
                const auto actual = row.benchmarkConfig();
                require(expected.has_value() && actual.has_value(),
                        "canonical Creator row selection did not create a config");
                requireConfigsEqual(*actual, *expected);
                require(actual->profile == profile.id && actual->operation == operation,
                        "Creator row changed canonical profile or operation");
                require(ConfigValidator{}.validate(*actual).isValid(),
                        "registry-derived selection failed the domain validator");
                ++inputModeCaseCount;
            };

            if (profile.category == PrimitiveCategory::Signature
                && (operation == BenchmarkOperation::Sign
                    || operation == BenchmarkOperation::Verify)) {
                const auto controls = selectionControlsFor(profile.id, operation, std::nullopt);
                for (const auto mode : controls.signatureInputModes) {
                    appendCase(mode);
                }
            } else {
                appendCase(std::nullopt);
            }
        }
    }
    require(profileCount == 72, "all profile coverage count changed");
    require(operationPairCount == 139, "profile-operation coverage count changed");
    require(inputModeCaseCount == 175, "input-mode-aware coverage count changed");
}

void testCapabilitySpecificConfigConstruction()
{
    const auto signatureProfiles = profilesForCategory(PrimitiveCategory::Signature);
    const auto keyGenProfile = signatureProfiles.front()->id;
    auto keyGen = benchmarkConfigFromSelection({
        PrimitiveCategory::Signature, keyGenProfile, BenchmarkOperation::KeyGen,
        std::nullopt, 4096, 1, 1});
    require(keyGen.has_value()
                && std::holds_alternative<SignatureConfig>(keyGen->parameters)
                && std::holds_alternative<NoSignatureInput>(
                    std::get<SignatureConfig>(keyGen->parameters).input),
            "Signature KeyGen did not construct no-input configuration");

    const auto rsaProfile = AlgorithmProfileId::RsaPss2048Sha256;
    const auto prehashed = benchmarkConfigFromSelection({
        PrimitiveCategory::Signature, rsaProfile, BenchmarkOperation::Sign,
        SignatureInputMode::Prehashed, 4096, 1, 1});
    require(prehashed.has_value()
                && std::holds_alternative<PrehashedInput>(
                    std::get<SignatureConfig>(prehashed->parameters).input),
            "Prehashed selection did not construct the prehashed alternative");

    const auto message = benchmarkConfigFromSelection({
        PrimitiveCategory::Signature, rsaProfile, BenchmarkOperation::Verify,
        SignatureInputMode::Message, 777, 1, 1});
    require(message.has_value()
                && std::get<MessageInput>(
                    std::get<SignatureConfig>(message->parameters).input).messageSize == 777,
            "Message selection did not preserve workload size");

    const auto messageOnly = selectionControlsFor(
        AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, std::nullopt);
    require(messageOnly.signatureInputModes.size() == 1
                && messageOnly.signatureInputModes.front() == SignatureInputMode::Message,
            "MessageOnly profile exposed an unsupported mode");
    require(!benchmarkConfigFromSelection({
                PrimitiveCategory::Signature, AlgorithmProfileId::Ed25519,
                BenchmarkOperation::Sign, SignatureInputMode::Prehashed, 64, 1, 1}),
            "MessageOnly profile accepted Prehashed");

    const auto keyEstablishment = benchmarkConfigFromSelection({
        PrimitiveCategory::KeyEstablishment, AlgorithmProfileId::X25519,
        BenchmarkOperation::Derive, std::nullopt, 4096, 1, 1});
    require(keyEstablishment.has_value()
                && std::holds_alternative<KeyEstablishmentConfig>(
                    keyEstablishment->parameters),
            "key establishment leaked workload input");

    const auto aead = benchmarkConfigFromSelection({
        PrimitiveCategory::Aead, AlgorithmProfileId::Aes128Gcm,
        BenchmarkOperation::Encrypt, std::nullopt, 512, 1, 1});
    require(aead.has_value() && std::holds_alternative<AeadConfig>(aead->parameters)
                && std::get<AeadConfig>(aead->parameters).plaintextSize == 512,
            "AEAD selection did not construct plaintext input");

    const auto hash = benchmarkConfigFromSelection({
        PrimitiveCategory::HashXof, AlgorithmProfileId::Sha256,
        BenchmarkOperation::Hash, std::nullopt, 0, 1, 1});
    require(hash.has_value() && std::holds_alternative<HashConfig>(hash->parameters)
                && std::get<HashConfig>(hash->parameters).inputSize == 0,
            "Hash did not preserve zero-byte workload");
    const auto xofProfiles = profilesForCategory(PrimitiveCategory::HashXof);
    const auto xofProfile = std::find_if(xofProfiles.begin(), xofProfiles.end(),
        [](const AlgorithmProfile* profile) {
            return profile->operations.contains(BenchmarkOperation::Xof);
        });
    require(xofProfile != xofProfiles.end(), "registry has no XOF profile");
    const auto xof = benchmarkConfigFromSelection({
        PrimitiveCategory::HashXof, (*xofProfile)->id,
        BenchmarkOperation::Xof, std::nullopt, 1234, 1, 1});
    require(xof.has_value() && std::holds_alternative<HashConfig>(xof->parameters)
                && std::get<HashConfig>(xof->parameters).inputSize == 1234,
            "XOF selection did not construct input-size parameters");

    require(!benchmarkConfigFromSelection({
                PrimitiveCategory::Aead, AlgorithmProfileId::Sha256,
                BenchmarkOperation::Hash, std::nullopt, 1, 1, 1}),
            "incoherent category/profile selection was accepted");
    require(!benchmarkConfigFromSelection({
                PrimitiveCategory::Signature, rsaProfile, BenchmarkOperation::KeyGen,
                std::nullopt, 1, 1, 1}),
            "incoherent profile/operation selection was accepted");
}

void testCreatorRowDynamicInputs()
{
    BatchCreatorWidget creator;
    require(creator.rowCount() == 0, "creator did not start empty");
    require(creator.addRow(), "creator could not add its first row");
    auto* row = creator.rowAt(0);
    require(row != nullptr, "new creator row was unavailable");
    auto config = row->benchmarkConfig();
    require(config.has_value()
                && std::holds_alternative<SignatureConfig>(config->parameters)
                && std::holds_alternative<NoSignatureInput>(
                    std::get<SignatureConfig>(config->parameters).input),
            "default Signature KeyGen row was incomplete");
    require(row->signatureInputModeComboBox()->isHidden()
                && row->workloadSizeSpinBox()->isHidden(),
            "Signature KeyGen displayed irrelevant input controls");

    selectData(row->profileComboBox(), static_cast<int>(AlgorithmProfileId::RsaPss2048Sha256));
    selectData(row->operationComboBox(), static_cast<int>(BenchmarkOperation::Sign));
    require(row->signatureInputModeComboBox()->count() == 2,
            "RSA-PSS row did not expose both signature modes");
    require(row->signatureInputModeComboBox()->currentData().toInt()
                == static_cast<int>(SignatureInputMode::Prehashed)
                && row->workloadSizeSpinBox()->isHidden(),
            "Prehashed selection displayed message workload");
    config = row->benchmarkConfig();
    require(config.has_value()
                && std::holds_alternative<PrehashedInput>(
                    std::get<SignatureConfig>(config->parameters).input),
            "Prehashed row configuration was not constructed");

    selectData(row->signatureInputModeComboBox(), static_cast<int>(SignatureInputMode::Message));
    row->workloadSizeSpinBox()->setValue(999);
    config = row->benchmarkConfig();
    require(config.has_value() && !row->workloadSizeSpinBox()->isHidden()
                && std::get<MessageInput>(
                    std::get<SignatureConfig>(config->parameters).input).messageSize == 999,
            "Message row did not expose and preserve its workload");

    selectData(row->profileComboBox(), static_cast<int>(AlgorithmProfileId::Ed25519));
    require(row->signatureInputModeComboBox()->count() == 1
                && row->signatureInputModeComboBox()->currentData().toInt()
                    == static_cast<int>(SignatureInputMode::Message),
            "MessageOnly row exposed an unsupported signature mode");

    selectData(row->categoryComboBox(), static_cast<int>(PrimitiveCategory::KeyEstablishment));
    config = row->benchmarkConfig();
    require(config.has_value()
                && std::holds_alternative<KeyEstablishmentConfig>(config->parameters)
                && row->signatureInputModeComboBox()->isHidden()
                && row->workloadSizeSpinBox()->isHidden(),
            "Key-establishment row retained obsolete workload parameters");

    selectData(row->categoryComboBox(), static_cast<int>(PrimitiveCategory::Aead));
    config = row->benchmarkConfig();
    require(config.has_value() && std::holds_alternative<AeadConfig>(config->parameters)
                && row->workloadSizeSpinBox()->minimum() == 1,
            "AEAD row did not expose a positive plaintext workload");

    selectData(row->categoryComboBox(), static_cast<int>(PrimitiveCategory::HashXof));
    selectData(row->profileComboBox(), static_cast<int>(AlgorithmProfileId::Sha256));
    selectData(row->operationComboBox(), static_cast<int>(BenchmarkOperation::Hash));
    require(row->workloadSizeSpinBox()->minimum() == 0,
            "Hash row did not allow zero input bytes");
    row->workloadSizeSpinBox()->setValue(0);
    config = row->benchmarkConfig();
    require(config.has_value() && std::holds_alternative<HashConfig>(config->parameters)
                && std::get<HashConfig>(config->parameters).inputSize == 0,
            "Hash row did not preserve zero-byte input");

    const auto xofProfiles = profilesForCategory(PrimitiveCategory::HashXof);
    const auto xofProfile = std::find_if(xofProfiles.begin(), xofProfiles.end(),
        [](const AlgorithmProfile* profile) {
            return profile->operations.contains(BenchmarkOperation::Xof);
        });
    require(xofProfile != xofProfiles.end(), "registry has no XOF profile");
    selectData(row->profileComboBox(), static_cast<int>((*xofProfile)->id));
    config = row->benchmarkConfig();
    require(config.has_value() && config->operation == BenchmarkOperation::Xof
                && std::holds_alternative<HashConfig>(config->parameters),
            "XOF row did not construct canonical input configuration");
}

void testCreatorRowActionsAndStateIndependence()
{
    BatchCreatorWidget creator;
    require(!creator.deleteRow(0) && !creator.cloneRow(0)
                && !creator.moveRowUp(0) && !creator.moveRowDown(0),
            "empty creator accepted an invalid row operation");
    creator.addRowButton()->click();
    require(creator.addRow() && creator.addRow(),
            "creator failed to add rows");
    creator.rowAt(0)->iterationsSpinBox()->setValue(11);
    creator.rowAt(1)->iterationsSpinBox()->setValue(22);
    creator.rowAt(2)->iterationsSpinBox()->setValue(33);
    auto* source = creator.rowAt(1);
    selectData(source->profileComboBox(),
               static_cast<int>(AlgorithmProfileId::RsaPss2048Sha256));
    selectData(source->operationComboBox(), static_cast<int>(BenchmarkOperation::Sign));
    selectData(source->signatureInputModeComboBox(),
               static_cast<int>(SignatureInputMode::Message));
    source->workloadSizeSpinBox()->setValue(555);
    require(!creator.moveRowUp(0) && !creator.moveRowDown(2),
            "creator moved a row beyond an ordering boundary");
    require(!creator.rowAt(0)->moveUpButton()->isEnabled()
                && !creator.rowAt(2)->moveDownButton()->isEnabled(),
            "row boundary controls were not disabled");

    auto* edit = creator.rowAt(1)->iterationsSpinBox()->findChild<QLineEdit*>();
    require(edit != nullptr, "iterations editor was not accessible");
    edit->setText(QStringLiteral("222"));
    creator.rowAt(1)->cloneButton()->click();
    require(creator.rowCount() == 4
                && creator.rowAt(1)->state().iterationsPerRun == 222
                && creator.rowAt(2)->state().iterationsPerRun == 222
                && creator.rowAt(2)->state().profile == AlgorithmProfileId::RsaPss2048Sha256
                && creator.rowAt(2)->state().signatureInputMode == SignatureInputMode::Message
                && creator.rowAt(2)->state().workloadSizeBytes == 555,
            "clone did not capture the actively edited spin-box value");
    const auto originalConfig = creator.rowAt(1)->benchmarkConfig();
    const auto clonedConfig = creator.rowAt(2)->benchmarkConfig();
    require(originalConfig.has_value() && clonedConfig.has_value()
                && originalConfig->profile == clonedConfig->profile
                && originalConfig->operation == clonedConfig->operation
                && originalConfig->iterationsPerRun == clonedConfig->iterationsPerRun
                && originalConfig->runs == clonedConfig->runs
                && std::get<MessageInput>(
                    std::get<SignatureConfig>(originalConfig->parameters).input).messageSize
                    == std::get<MessageInput>(
                        std::get<SignatureConfig>(clonedConfig->parameters).input).messageSize,
            "cloned rows did not retain equivalent configurations");

    creator.rowAt(2)->iterationsSpinBox()->setValue(444);
    require(creator.rowAt(1)->state().iterationsPerRun == 222
                && creator.rowAt(2)->state().iterationsPerRun == 444,
            "editing a clone changed the original row state");
    creator.rowAt(2)->moveUpButton()->click();
    require(creator.rowAt(1)->state().iterationsPerRun == 444
                && creator.rowAt(2)->state().iterationsPerRun == 222,
            "moving rows changed their state or order");
    creator.rowAt(1)->moveDownButton()->click();
    require(creator.rowAt(2)->state().iterationsPerRun == 444,
            "moving down did not preserve the moved row");
    creator.rowAt(1)->deleteButton()->click();
    require(creator.rowCount() == 3 && creator.rowAt(1)->state().iterationsPerRun == 444,
            "deleting a row changed an unrelated row");
    require(creator.rowAt(0)->moveUpButton()->isEnabled()
                == false && creator.rowAt(0)->moveDownButton()->isEnabled(),
            "move boundary state was not refreshed after deletion");
}

void testCreatorFinalization()
{
    BatchCreatorWidget emptyCreator;
    const auto empty = emptyCreator.finalizeRows();
    require(!empty.isValid() && !empty.issues.isEmpty()
                && empty.issues.front().contains(QStringLiteral("/entries")),
            "empty Creator draft was not rejected by the shared parser");

    BatchCreatorWidget creator;
    require(creator.addRow() && creator.addRow() && creator.addRow(),
            "Creator could not construct finalization entries");
    configureHashRow(creator.rowAt(0), 64, 10, 2);
    configureHashRow(creator.rowAt(1), 64, 10, 2);
    configureHashRow(creator.rowAt(2), 128, 5, 4);

    const auto finalized = creator.finalizeRows();
    require(finalized.isValid() && finalized.definition->entries().size() == 3,
            "valid Creator rows did not finalize");
    require(finalized.inputBytes.contains("\n    \"entries\"")
                && !finalized.inputBytes.contains("\"id\""),
            "finalization did not retain canonical pretty Batch input without IDs");
    const auto& entries = finalized.definition->entries();
    require(entries[0].entryIndex == 1 && entries[1].entryIndex == 2
                && entries[2].entryIndex == 3
                && !entries[0].id.has_value() && !entries[1].id.has_value()
                && !entries[2].id.has_value(),
            "finalization changed visual order, indices, or optional IDs");
    require(application::benchmarkConfigToJson(entries[0].config)
                == application::benchmarkConfigToJson(entries[1].config)
                && application::benchmarkConfigToJson(entries[2].config)
                    != application::benchmarkConfigToJson(entries[1].config),
            "finalization did not preserve duplicate/differing configurations");
    require(finalized.inputBytes == application::BatchInputDocumentBuilder{}.build({
                entries[0].config, entries[1].config, entries[2].config}),
            "finalization returned bytes other than the canonical builder output");
    const auto parsed = application::BatchInputParser{}.parseData(finalized.inputBytes);
    require(parsed.definition.has_value() && parsed.issues.empty()
                && parsed.definition->entries().size() == entries.size(),
            "finalized bytes did not use the authoritative in-memory parser");

    creator.rowAt(1)->iterationsSpinBox()->setValue(1'000'000'000);
    creator.rowAt(1)->runsSpinBox()->setValue(2);
    const auto invalidBudget = creator.finalizeRows();
    require(!invalidBudget.isValid() && invalidBudget.issues.size() == 1
                && invalidBudget.issues.front().contains(QStringLiteral("Entry 2"))
                && invalidBudget.issues.front().contains(QStringLiteral("/entries/1"))
                && invalidBudget.issues.front().contains(QStringLiteral("seriesIterationBudgetExceeded")),
            "invalid N*M finalization lacked a precise parser diagnostic");
}

void testCreatorMaximumRowCount()
{
    BatchCreatorWidget creator;
    QElapsedTimer constructionTimer;
    constructionTimer.start();
    for (int index = 0; index < BatchCreatorWidget::kMaximumRows; ++index) {
        require(creator.addRow(), "creator rejected an allowed row before the maximum");
    }
    const auto constructionMilliseconds = constructionTimer.elapsed();
    require(creator.rowCount() == BatchCreatorWidget::kMaximumRows
                && !creator.addRow() && !creator.cloneRow(0)
                && !creator.addRowButton()->isEnabled()
                && !creator.rowAt(0)->cloneButton()->isEnabled(),
            "creator did not enforce the 1000-row editing limit");
    auto* editedRow = creator.rowAt(500);
    editedRow->iterationsSpinBox()->setValue(12345);
    require(creator.rowAt(500)->state().iterationsPerRun == 12345
                && creator.rowCount() == BatchCreatorWidget::kMaximumRows
                && creator.rowAt(500) == editedRow,
            "editing one row altered creator row structure");

    configureHashRow(creator.rowAt(0), 0, 10, 2);
    configureHashRow(creator.rowAt(500), 4096, 20, 3);
    configureHashRow(creator.rowAt(999), 8192, 30, 4);
    require(creator.moveRowUp(999) && creator.moveRowDown(998)
                && creator.rowCount() == BatchCreatorWidget::kMaximumRows,
            "1000-row ordering operation changed row count");

    QElapsedTimer finalizationTimer;
    finalizationTimer.start();
    const auto finalized = creator.finalizeRows();
    const auto finalizationMilliseconds = finalizationTimer.elapsed();
    require(finalized.isValid()
                && finalized.definition->entries().size()
                    == BatchCreatorWidget::kMaximumRows,
            "1000 real Creator rows did not finalize");

    QTemporaryDir directory;
    require(directory.isValid(), "Creator stress export directory could not be created");
    const auto outputPath = directory.filePath(QStringLiteral("creator-1000.json"));
    QElapsedTimer exportTimer;
    exportTimer.start();
    const auto writeResult =
        application::AtomicFileWriter{}.writeAtomically(outputPath, finalized.inputBytes);
    require(writeResult.success, "atomic 1000-row Creator export failed");
    QFile exportedFile(outputPath);
    require(exportedFile.open(QIODevice::ReadOnly),
            "1000-row Creator export could not be read");
    const auto exportedBytes = exportedFile.readAll();
    require(exportedBytes == finalized.inputBytes,
            "1000-row Creator export was not byte-identical to finalized input");
    const auto parsedFile = application::BatchInputParser{}.parseFile(outputPath);
    const auto exportAndParseMilliseconds = exportTimer.elapsed();
    require(parsedFile.definition.has_value() && parsedFile.issues.empty()
                && parsedFile.definition->entries().size()
                    == BatchCreatorWidget::kMaximumRows,
            "1000-row exported Creator input did not round-trip through parseFile");
    for (std::size_t index = 0; index < parsedFile.definition->entries().size(); ++index) {
        const auto& memoryEntry = finalized.definition->entries()[index];
        const auto& fileEntry = parsedFile.definition->entries()[index];
        require(fileEntry.entryIndex == index + 1
                    && fileEntry.entryIndex == memoryEntry.entryIndex
                    && !fileEntry.id.has_value()
                    && application::benchmarkConfigToJson(fileEntry.config)
                        == application::benchmarkConfigToJson(memoryEntry.config)
                    && fileEntry.characteristics.index() == memoryEntry.characteristics.index(),
                "1000-row Creator file roundtrip changed order or entry semantics");
    }
    std::cout << "EVIDENCE creator_1000 construction_ms=" << constructionMilliseconds
              << " finalize_ms=" << finalizationMilliseconds
              << " atomic_export_parseFile_ms=" << exportAndParseMilliseconds << '\n';
    QCoreApplication::processEvents();
}

} // namespace
} // namespace cryptobench::tests

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    try {
        cryptobench::tests::testRegistryDrivenSelectionCoverage();
        std::cout << "PASS canonical GUI selection: 72 profiles, 139 pairs, 175 cases\n";
        cryptobench::tests::testCapabilitySpecificConfigConstruction();
        std::cout << "PASS typed primitive config construction\n";
        cryptobench::tests::testCreatorRowDynamicInputs();
        std::cout << "PASS Creator dynamic input controls\n";
        cryptobench::tests::testCreatorRowActionsAndStateIndependence();
        std::cout << "PASS Creator row actions, ordering, and independence\n";
        cryptobench::tests::testCreatorFinalization();
        std::cout << "PASS Creator finalization and parser diagnostics\n";
        cryptobench::tests::testCreatorMaximumRowCount();
        std::cout << "PASS Creator 1000-row limit\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL Creator GUI tests: " << error.what() << '\n';
        return 1;
    }
}
