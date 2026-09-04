package testmanagerd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/danielpaulus/go-ios/ios/nskeyedarchiver"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// TestListener collects test results from the test execution
type TestListener struct {
	stateMu              sync.RWMutex
	writerMu             sync.Mutex
	sharedWriterMu       *sync.Mutex
	finished             chan struct{}
	finishedOnce         sync.Once
	err                  error
	logWriter            io.Writer
	debugLogWriter       io.Writer
	attachmentsDirectory string
	writeAttachment      func(string, []byte) error
	TestSuites           []TestSuite
	runningTestSuite     *TestSuite
	nextSuiteIdentity    uint64
}

type TestSuite struct {
	Name          string
	StartDate     time.Time
	EndDate       time.Time
	TestDuration  time.Duration
	TotalDuration time.Duration
	TestCases     []TestCase
	identity      uint64
}

type TestCase struct {
	ClassName   string
	MethodName  string
	Status      TestCaseStatus
	Err         TestError
	Duration    time.Duration
	Attachments []TestAttachment
}

type TestCaseStatus string

const (
	StatusFailed          = TestCaseStatus("failed")           // Defined by Apple
	StatusPassed          = TestCaseStatus("passed")           // Defined by Apple
	StatusExpectedFailure = TestCaseStatus("expected failure") // Defined by Apple
	StatusStalled         = TestCaseStatus("stalled")          // Defined by us

	// Test suite counter constants
	unknownCount uint64 = 0
)

type TestError struct {
	Message string
	File    string
	Line    uint64
}

type TestAttachment struct {
	Name                  string
	Path                  string
	Type                  string
	Timestamp             float64
	Activity              string
	UniformTypeIdentifier string
}

func NewTestListener(logWriter io.Writer, debugLogWriter io.Writer, attachmentsDirectory string) *TestListener {
	return &TestListener{
		finished:             make(chan struct{}),
		logWriter:            logWriter,
		debugLogWriter:       debugLogWriter,
		TestSuites:           make([]TestSuite, 0),
		attachmentsDirectory: attachmentsDirectory,
	}
}

func (t *TestListener) didFinishExecutingTestPlan() {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	t.executionFinishedLocked()
}

func (t *TestListener) initializationForUITestingDidFailWithError(err nskeyedarchiver.NSError) {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	t.err = err
	t.executionFinishedLocked()
}

func (t *TestListener) didFailToBootstrapWithError(err nskeyedarchiver.NSError) {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	t.err = err
	t.executionFinishedLocked()
}

func (t *TestListener) testCaseStalled(testClass string, method string, file string, line uint64) {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	testCase := t.findTestCaseLocked(testClass, method)
	if testCase != nil {
		testCase.Status = StatusStalled
		testCase.Err = TestError{
			Message: "Test case stalled",
			File:    file,
			Line:    line,
		}
	}
}

func (t *TestListener) testCaseFinished(testClass string, testMethod string, xcActivityRecord nskeyedarchiver.XCActivityRecord) {
	t.stateMu.Lock()
	target, ok := t.attachmentTargetLocked(testClass, testMethod)
	t.stateMu.Unlock()
	if !ok {
		log.Debug(fmt.Sprintf("Received testCaseFinished for %s:%s without initialization", testClass, testMethod))
		return
	}

	attachments := t.persistAttachments(xcActivityRecord)
	if len(attachments) == 0 {
		return
	}

	t.stateMu.Lock()
	testCase := t.findAttachmentTargetLocked(target)
	if testCase == nil {
		t.stateMu.Unlock()
		removeAttachments(attachments)
		log.Debug(fmt.Sprintf("Received testCaseFinished for %s:%s after its test suite was discarded", testClass, testMethod))
		return
	}
	testCase.Attachments = append(testCase.Attachments, attachments...)
	t.stateMu.Unlock()
}

type attachmentTarget struct {
	suiteIdentity uint64
	caseIndex     int
}

func (t *TestListener) attachmentTargetLocked(testClass string, testMethod string) (attachmentTarget, bool) {
	ts := t.findTestSuiteLocked(testClass)
	testCase := t.findTestCaseLocked(testClass, testMethod)
	if ts == nil || testCase == nil || testClass == "none" || testMethod == "none" {
		// Apple reports some activity attachments under a synthetic "none" case.
		ts = t.runningTestSuite
		if ts == nil || len(ts.TestCases) == 0 {
			return attachmentTarget{}, false
		}
		testCase = &ts.TestCases[len(ts.TestCases)-1]
	}
	caseIndex := -1
	for index := range ts.TestCases {
		if &ts.TestCases[index] == testCase {
			caseIndex = index
			break
		}
	}
	if caseIndex < 0 {
		return attachmentTarget{}, false
	}
	if ts.identity == 0 {
		t.nextSuiteIdentity++
		ts.identity = t.nextSuiteIdentity
	}
	return attachmentTarget{suiteIdentity: ts.identity, caseIndex: caseIndex}, true
}

func (t *TestListener) findAttachmentTargetLocked(target attachmentTarget) *TestCase {
	if testCase := testCaseForAttachmentTarget(t.runningTestSuite, target); testCase != nil {
		return testCase
	}
	for index := range t.TestSuites {
		if testCase := testCaseForAttachmentTarget(&t.TestSuites[index], target); testCase != nil {
			return testCase
		}
	}
	return nil
}

func testCaseForAttachmentTarget(suite *TestSuite, target attachmentTarget) *TestCase {
	if suite == nil || suite.identity != target.suiteIdentity || target.caseIndex < 0 || target.caseIndex >= len(suite.TestCases) {
		return nil
	}
	return &suite.TestCases[target.caseIndex]
}

func (t *TestListener) persistAttachments(xcActivityRecord nskeyedarchiver.XCActivityRecord) []TestAttachment {
	attachments := make([]TestAttachment, 0, len(xcActivityRecord.Attachments))
	writeAttachment := t.writeAttachment
	if writeAttachment == nil {
		writeAttachment = func(path string, payload []byte) error {
			return os.WriteFile(path, payload, 0o666)
		}
	}
	for _, attachment := range xcActivityRecord.Attachments {
		attachmentsPath := filepath.Join(t.attachmentsDirectory, uuid.New().String())
		if err := writeAttachment(attachmentsPath, attachment.Payload); err != nil {
			log.WithFields(log.Fields{"error": err, "attachment": attachment.Name}).Warn("Received testCaseFinished with activity record but failed writing attachments to disk. Ignoring attachment")
			continue
		}
		attachments = append(attachments, TestAttachment{
			Name:                  strings.Clone(attachment.Name),
			Timestamp:             attachment.Timestamp,
			Activity:              strings.Clone(xcActivityRecord.Title),
			Path:                  attachmentsPath,
			Type:                  strings.Clone(xcActivityRecord.ActivityType),
			UniformTypeIdentifier: strings.Clone(attachment.UniformTypeIdentifier),
		})
	}
	return attachments
}

func removeAttachments(attachments []TestAttachment) {
	for _, attachment := range attachments {
		if err := os.Remove(attachment.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.WithFields(log.Fields{"error": err, "attachment": attachment.Name}).Warn("Failed cleaning up an unclaimed test attachment")
		}
	}
}

func (t *TestListener) testSuiteDidStart(suiteName string, date string) {
	d, err := time.Parse(time.DateTime+" +0000", date)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("Cannot parse test suite start date")
		d = time.Now()
	}
	t.stateMu.Lock()
	defer t.stateMu.Unlock()

	if t.runningTestSuite != nil {
		log.Warn("A new test suite starts running while another one is in progress, finalizing the previous one")
		t.TestSuites = append(t.TestSuites, *t.runningTestSuite)
	}

	t.runningTestSuite = &TestSuite{
		Name:      suiteName,
		StartDate: d,
		TestCases: make([]TestCase, 0),
	}
}

func (t *TestListener) testCaseDidStartForClass(testClass string, testMethod string) {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	// Find the existing test suite or create a new one if not found
	ts := t.findTestSuiteLocked(testClass)
	if ts == nil {
		// If no test suite is found and we're not in a running test suite,
		// we should use the runningTestSuite instead of creating a new one.
		// This handles cases where testCaseDidStartForClass is called before
		// testSuiteDidStart, which would otherwise result in a nil pointer dereference.

		if t.runningTestSuite != nil {
			ts = t.runningTestSuite
		} else {
			// Create a new test suite for this class if no running suite exists.
			// We initialize TestCases as an empty slice to avoid potential issues with nil slices.
			d := time.Now()
			newSuite := TestSuite{
				Name:      testClass,
				StartDate: d,
				TestCases: []TestCase{},
			}
			t.TestSuites = append(t.TestSuites, newSuite)
			ts = &t.TestSuites[len(t.TestSuites)-1]
		}
	}

	// Add the test case to the suite
	ts.TestCases = append(ts.TestCases, TestCase{
		ClassName:  testClass,
		MethodName: testMethod,
	})
}

func (t *TestListener) testCaseFailedForClass(testClass string, testMethod string, message string, file string, line uint64) {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	testCase := t.findTestCaseLocked(testClass, testMethod)
	if testCase == nil {
		log.Warn("Received failure status for an unknown test, adding it to suite")
		ts := t.findTestSuiteLocked(testClass)
		if ts == nil {
			log.Warn("Received failure status without a running test suite, ignoring it")
			return
		}
		ts.TestCases = append(ts.TestCases, TestCase{
			ClassName:  testClass,
			MethodName: testMethod,
		})
		testCase = &ts.TestCases[len(ts.TestCases)-1]
	}

	testCase.Status = StatusFailed
	testCase.Err = TestError{
		Message: message,
		File:    file,
		Line:    line,
	}
}

func (t *TestListener) testCaseDidFinishForTest(testClass string, testMethod string, status string, duration float64) {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	testCase := t.findTestCaseLocked(testClass, testMethod)
	if testCase != nil {
		// We override "failed" status for stalled tests with the value "stalled" to be able to distinguish them later
		if testCase.Status != StatusStalled {
			testCase.Status = TestCaseStatus(status)
		}

		d, err := time.ParseDuration(fmt.Sprintf("%f", duration) + "s")
		if err != nil {
			d = 0
			log.WithFields(log.Fields{"error": err}).Warn("Failed parsing test case duration")
		}

		testCase.Duration = d
	}
}

func (t *TestListener) testSuiteFinished(suiteName string, date string, testCount uint64, failures uint64, skip uint64, expectedFailure uint64, unexpectedFailure uint64, uncaughtException uint64, testDuration float64, totalDuration float64) {
	endDate, err := time.Parse(time.DateTime+" +0000", date)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("Cannot parse test suite start date")
		endDate = time.Now()
	}
	t.stateMu.Lock()
	defer t.stateMu.Unlock()

	ts := t.findTestSuiteLocked(suiteName)
	if ts == nil {
		log.Debug(fmt.Sprintf("Received testSuiteFinished for %s without initialization", suiteName))
		return
	}

	ts.EndDate = endDate

	d, err := time.ParseDuration(fmt.Sprintf("%f", testDuration) + "s")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("Test duration cannot be parsed")
		d = 0
	}
	ts.TestDuration = d

	d, err = time.ParseDuration(fmt.Sprintf("%f", totalDuration) + "s")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("Total duration cannot be parsed")
		d = 0
	}
	ts.TotalDuration = d

	t.TestSuites = append(t.TestSuites, *t.runningTestSuite)
	t.runningTestSuite = nil
}

func (t *TestListener) LogMessage(msg string) {
	_, _ = t.Write([]byte(msg))
}

// Write serializes writes to the listener's primary log writer. It lets
// stdout forwarding and DTX log callbacks share even non-thread-safe writers.
func (t *TestListener) Write(p []byte) (int, error) {
	writerMu := t.outputWriterMutex()
	writerMu.Lock()
	defer writerMu.Unlock()
	return t.logWriter.Write(p)
}

func (t *TestListener) LogDebugMessage(msg string) {
	writerMu := t.outputWriterMutex()
	writerMu.Lock()
	defer writerMu.Unlock()
	_, _ = t.debugLogWriter.Write([]byte(msg))
}

func (t *TestListener) outputWriterMutex() *sync.Mutex {
	if t.sharedWriterMu != nil {
		return t.sharedWriterMu
	}
	return &t.writerMu
}

// newTargetListener isolates all mutable XCTest state while preserving the
// caller's output destinations. The shared writer mutex also serializes a
// late stdout copy from an old target with callbacks from the next target.
func (t *TestListener) newTargetListener() *TestListener {
	return &TestListener{
		sharedWriterMu:       t.outputWriterMutex(),
		finished:             make(chan struct{}),
		logWriter:            t.logWriter,
		debugLogWriter:       t.debugLogWriter,
		attachmentsDirectory: t.attachmentsDirectory,
		writeAttachment:      t.writeAttachment,
		TestSuites:           make([]TestSuite, 0),
	}
}

func (t *TestListener) TestRunnerKilled() {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	t.err = errors.New("Test runner has been explicitly killed.")
	t.executionFinishedLocked()
}

func (t *TestListener) FinishWithError(err error) {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	if t.runningTestSuite != nil {
		t.TestSuites = append(t.TestSuites, *t.runningTestSuite)
		t.runningTestSuite = nil
	}
	t.err = err
	t.executionFinishedLocked()
}

func (t *TestListener) Done() <-chan struct{} {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return t.finished
}

// Result returns a deep snapshot of the completed test suites and the current
// terminal error. Callers may safely mutate the returned slices.
func (t *TestListener) Result() ([]TestSuite, error) {
	if t == nil {
		return nil, errors.New("test listener is nil")
	}
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return cloneTestSuites(t.TestSuites), t.err
}

func (t *TestListener) setError(err error) {
	if t == nil || err == nil {
		return
	}
	t.stateMu.Lock()
	t.err = err
	t.stateMu.Unlock()
}

func (t *TestListener) findTestCaseLocked(className string, methodName string) *TestCase {
	if ts := t.findTestSuiteLocked(className); ts != nil {
		if len(ts.TestCases) > 0 {
			tc := &ts.TestCases[len(ts.TestCases)-1]
			if tc.ClassName == className && tc.MethodName == methodName {
				return tc
			}
		}
	}

	if t.runningTestSuite != nil {
		// Search backwards to find the most recent matching test case without status
		for i := len(t.runningTestSuite.TestCases) - 1; i >= 0; i-- {
			tc := &t.runningTestSuite.TestCases[i]
			if tc.ClassName == className && tc.MethodName == methodName && tc.Status == "" {
				return tc
			}
		}
	}

	return nil
}

// findTestSuite returns a detached snapshot for callers that only need to
// inspect the currently running suite. Mutations must stay behind stateMu and
// use findTestSuiteLocked instead.
func (t *TestListener) findTestSuite(className string) *TestSuite {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	suite := t.findTestSuiteLocked(className)
	if suite == nil {
		return nil
	}
	cloned := cloneTestSuites([]TestSuite{*suite})
	return &cloned[0]
}

func (t *TestListener) findTestSuiteLocked(className string) *TestSuite {
	if t.runningTestSuite != nil {
		if t.runningTestSuite.Name == className {
			return t.runningTestSuite
		}
	}

	return nil
}

func (t *TestListener) executionFinishedLocked() {
	t.finishedOnce.Do(func() {
		close(t.finished)
	})
}

func (t *TestListener) reset() {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	// Reinitialize finished channel to allow signaling again
	t.finished = make(chan struct{})

	// Reset the sync.Once instance so it can be used again
	t.finishedOnce = sync.Once{}

	// Clear error from the previous test run
	t.err = nil

	// Reset test results
	t.TestSuites = nil

	// Clear the reference to the running test suite
	t.runningTestSuite = nil
}

func cloneTestSuites(suites []TestSuite) []TestSuite {
	if suites == nil {
		return nil
	}
	cloned := make([]TestSuite, len(suites))
	for suiteIndex := range suites {
		cloned[suiteIndex] = suites[suiteIndex]
		cloned[suiteIndex].identity = 0
		if suites[suiteIndex].TestCases == nil {
			continue
		}
		cloned[suiteIndex].TestCases = make([]TestCase, len(suites[suiteIndex].TestCases))
		for caseIndex := range suites[suiteIndex].TestCases {
			cloned[suiteIndex].TestCases[caseIndex] = suites[suiteIndex].TestCases[caseIndex]
			cloned[suiteIndex].TestCases[caseIndex].Attachments = append(
				[]TestAttachment(nil),
				suites[suiteIndex].TestCases[caseIndex].Attachments...,
			)
		}
	}
	return cloned
}
