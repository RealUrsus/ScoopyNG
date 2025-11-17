/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * File: IDetectionTest.h
 * Purpose: Abstract base interface for all detection tests
 */

#pragma once

#include "DetectionTypes.h"
#include <string>
#include <memory>

// ============================================================================
// Abstract Detection Test Interface
// ============================================================================

class IDetectionTest {
public:
    virtual ~IDetectionTest() = default;

    // Execute the detection test
    virtual TestResult Execute() = 0;

    // Get test metadata
    virtual const char* GetTestName() const = 0;
    virtual const char* GetDescription() const = 0;
    virtual uint32_t GetTestId() const = 0;
    virtual HypervisorType GetTargetHypervisor() const = 0;

    // Platform support check
    virtual bool IsPlatformSupported() const {
#if defined(_M_X64)
        return true;
#elif defined(_M_IX86)
        return true;
#else
        return false;
#endif
    }
};

// ============================================================================
// Smart Pointer Type for Tests
// ============================================================================

using DetectionTestPtr = std::unique_ptr<IDetectionTest>;

// ============================================================================
// Test Factory Macro
// ============================================================================

#define DECLARE_DETECTION_TEST(ClassName, TestName, TestDesc, TestID, HVType) \
class ClassName : public IDetectionTest { \
public: \
    TestResult Execute() override; \
    const char* GetTestName() const override { return TestName; } \
    const char* GetDescription() const override { return TestDesc; } \
    uint32_t GetTestId() const override { return TestID; } \
    HypervisorType GetTargetHypervisor() const override { return HVType; } \
}
