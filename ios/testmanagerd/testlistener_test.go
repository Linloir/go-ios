package testmanagerd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios/nskeyedarchiver"
	"github.com/stretchr/testify/assert"
)

func TestFinishExecutingTestPlan(t *testing.T) {
	t.Parallel()

	t.Run("Wait for test finish with single waiter", func(t *testing.T) {
		testListener := NewTestListener(os.Stdout, os.Stdout, os.TempDir())

		go func() {
			testListener.didFinishExecutingTestPlan()
		}()

		<-testListener.finished
	})

	t.Run("Wait for test finish with multiple waiters", func(t *testing.T) {
		testListener := NewTestListener(os.Stdout, os.Stdout, os.TempDir())

		var wg sync.WaitGroup
		wg.Add(2)

		testListener.didFinishExecutingTestPlan()

		go func() {
			<-testListener.Done()
			wg.Done()
		}()

		go func() {
			<-testListener.Done()
			wg.Done()
		}()

		wg.Wait()
	})

	t.Run("Check error on a failed test run", func(t *testing.T) {
		testListener := NewTestListener(os.Stdout, os.Stdout, os.TempDir())

		testListener.initializationForUITestingDidFailWithError(nskeyedarchiver.NSError{
			ErrorCode: 1, Domain: "testdomain", UserInfo: map[string]interface{}{}})

		<-testListener.Done()
		assert.Error(t, testListener.err)
	})

	t.Run("Check error on a failed test run with bootstrap error", func(t *testing.T) {
		testListener := NewTestListener(os.Stdout, os.Stdout, os.TempDir())

		testListener.didFailToBootstrapWithError(nskeyedarchiver.NSError{
			ErrorCode: 1, Domain: "testdomain", UserInfo: map[string]interface{}{}})

		<-testListener.Done()
		assert.Error(t, testListener.err)
	})

	t.Run("Check test log callbacks", func(t *testing.T) {
		logWriter := assertionWriter{}
		debugLogWriter := assertionWriter{}

		testListener := NewTestListener(&logWriter, &debugLogWriter, os.TempDir())

		testListener.LogMessage("log")
		testListener.LogDebugMessage("debug")

		assert.True(t, logWriter.hasBytes, "Test listener must receive test logs")
		assert.True(t, debugLogWriter.hasBytes, "Test listener must receive test debug logs")
	})

	t.Run("Check test suite creation", func(t *testing.T) {
		testListener := NewTestListener(io.Discard, io.Discard, os.TempDir())

		testListener.testSuiteDidStart("mysuite", "2024-01-16 15:36:43 +0000")
		testListener.testSuiteFinished("mysuite", "2024-01-16 15:36:44 +0000", 0, 0, 0, 0, 0, 0, 1.0, 1.0)
		testListener.testSuiteDidStart("mysuite2", "2024-01-17 16:36:45 +0000")
		testListener.testSuiteFinished("mysuite2", "2024-01-17 16:36:46 +0000", 0, 0, 0, 0, 0, 0, 1.0, 1.0)

		firstSuite := testListener.TestSuites[0]
		secondSuite := testListener.TestSuites[1]

		assert.Equal(t, 2, len(testListener.TestSuites))
		assert.Equal(t, 2024, firstSuite.StartDate.Year())
		assert.Equal(t, time.Month(1), firstSuite.StartDate.Month())
		assert.Equal(t, 16, firstSuite.StartDate.Day())
		assert.Equal(t, "mysuite", firstSuite.Name)

		assert.Equal(t, 2, len(testListener.TestSuites))
		assert.Equal(t, 2024, secondSuite.StartDate.Year())
		assert.Equal(t, time.Month(1), secondSuite.StartDate.Month())
		assert.Equal(t, 17, secondSuite.StartDate.Day())
		assert.Equal(t, "mysuite2", secondSuite.Name)
	})

	t.Run("Check test case creation", func(t *testing.T) {
		testListener := NewTestListener(io.Discard, io.Discard, os.TempDir())

		testListener.testSuiteDidStart("mysuite", "2024-01-16 15:36:43 +0000")
		testListener.testCaseDidStartForClass("mysuite", "mymethod")

		assert.Equal(t, 1, len(testListener.runningTestSuite.TestCases), "TestCase must be appended to list of test cases")
		assert.Equal(t, TestCase{
			ClassName:  "mysuite",
			MethodName: "mymethod",
		}, testListener.runningTestSuite.TestCases[0])
	})

	t.Run("Check test start invalid date", func(t *testing.T) {
		testListener := NewTestListener(io.Discard, io.Discard, os.TempDir())

		testListener.testSuiteDidStart("mysuite", "INVALIDDATE")
		testListener.testSuiteFinished("mysuite", "INVALIDDATE", 0, 0, 0, 0, 0, 0, 1.0, 1.0)

		assert.Equal(t, time.Now().Year(), testListener.TestSuites[0].StartDate.Year())
		assert.Equal(t, time.Now().Year(), testListener.TestSuites[0].EndDate.Year())
	})

	t.Run("Check test case failure", func(t *testing.T) {
		testListener := NewTestListener(io.Discard, io.Discard, os.TempDir())

		testListener.testSuiteDidStart("mysuite", "2024-01-16 15:36:43 +0000")
		testListener.testCaseDidStartForClass("mysuite", "mymethod")

		testListener.testCaseFailedForClass("mysuite", "mymethod", "error", "file://app.swift", 123)
		testListener.testSuiteFinished("mysuite", "2024-01-16 15:37:43 +0000", 0, 0, 0, 0, 0, 0, 1.0, 1.0)

		assert.Equal(t, 1, len(testListener.TestSuites[0].TestCases), "TestCase must be appended to list of test cases")
		assert.Equal(t, TestCaseStatus("failed"), testListener.TestSuites[0].TestCases[0].Status)
		assert.Equal(t, "error", testListener.TestSuites[0].TestCases[0].Err.Message)
		assert.Equal(t, "file://app.swift", testListener.TestSuites[0].TestCases[0].Err.File)
		assert.Equal(t, uint64(123), testListener.TestSuites[0].TestCases[0].Err.Line)
	})

	t.Run("Check test case finish", func(t *testing.T) {
		testListener := NewTestListener(io.Discard, io.Discard, os.TempDir())

		testListener.testSuiteDidStart("mysuite", "2024-01-16 15:36:43 +0000")
		testListener.testCaseDidStartForClass("mysuite", "mymethod")
		testListener.testCaseDidFinishForTest("mysuite", "mymethod", "passed", 1.0)

		t.Run("Check running test suite is saved on FinishWithError", func(t *testing.T) {
			testListener := NewTestListener(io.Discard, io.Discard, os.TempDir())

			testListener.testSuiteDidStart("mysuite", "2024-01-16 15:36:43 +0000")
			testListener.testCaseDidStartForClass("mysuite", "mymethod")
			testListener.FinishWithError(errors.New("test error"))

			assert.Equal(t, 1, len(testListener.TestSuites))
			assert.Equal(t, "mysuite", testListener.TestSuites[0].Name)
			assert.Equal(t, 1, len(testListener.TestSuites[0].TestCases))
		})

		assert.Equal(t, 1, len(testListener.runningTestSuite.TestCases), "TestCase must be appended to list of test cases")
		assert.Equal(t, TestCaseStatus("passed"), testListener.runningTestSuite.TestCases[0].Status)
		assert.Equal(t, 1.0, testListener.runningTestSuite.TestCases[0].Duration.Seconds())
	})

	t.Run("Check test suite finish", func(t *testing.T) {
		testListener := NewTestListener(io.Discard, io.Discard, os.TempDir())

		testListener.testSuiteDidStart("mysuite", "2024-01-16 15:36:43 +0000")
		testListener.testCaseDidStartForClass("mysuite", "mymethod1")
		testListener.testCaseDidFinishForTest("mysuite", "mymethod1", "passed", 1.0)
		testListener.testCaseDidStartForClass("mysuite", "mymethod2")
		testListener.testCaseDidFinishForTest("mysuite", "mymethod2", "passed", 1.0)
		testListener.testSuiteFinished("mysuite", "2024-01-16 15:36:44 +0000", 2, 0, 0, 0, 0, 0, 1.0, 2.0)

		assert.Equal(t, 2, len(testListener.TestSuites[0].TestCases), "TestCase must be appended to list of test cases")
		assert.Equal(t, TestCaseStatus("passed"), testListener.TestSuites[0].TestCases[0].Status)
		assert.Equal(t, TestCaseStatus("passed"), testListener.TestSuites[0].TestCases[1].Status)
		assert.Equal(t, 2.0, testListener.TestSuites[0].TotalDuration.Seconds())
		assert.Equal(t, 1, testListener.TestSuites[0].EndDate.Second()-testListener.TestSuites[0].StartDate.Second())
	})

	t.Run("Check test case stall", func(t *testing.T) {
		testListener := NewTestListener(io.Discard, io.Discard, os.TempDir())

		testListener.testSuiteDidStart("mysuite", "2024-01-16 15:36:43 +0000")
		testListener.testCaseDidStartForClass("mysuite", "mymethod1")
		testListener.testCaseStalled("mysuite", "mymethod1", "file://app.swift", 123)
		testListener.testCaseDidFinishForTest("mysuite", "mymethod1", "failed", 1.0)

		assert.Equal(t, 1, len(testListener.runningTestSuite.TestCases), "TestCase must be appended to list of test cases")
		assert.Equal(t, TestCaseStatus("stalled"), testListener.runningTestSuite.TestCases[0].Status)
	})

	t.Run("Check test case with attachments", func(t *testing.T) {
		testListener := NewTestListener(io.Discard, io.Discard, os.TempDir())

		payload := []byte("test")
		attachments := make([]nskeyedarchiver.XCTAttachment, 1)
		attachments[0] = nskeyedarchiver.XCTAttachment{
			Payload: payload,
		}

		// Suite start
		testListener.testSuiteDidStart("mysuite", "2024-01-16 15:36:43 +0000")

		// Test with 0 attachments
		testListener.testCaseDidStartForClass("mysuite", "mymethod1")
		testListener.testCaseDidFinishForTest("mysuite", "mymethod1", "failed", 1.0)

		// Test with 1 attachment
		testListener.testCaseDidStartForClass("mysuite", "mymethod2")
		// Attachments of activity records are reported under a special test class named "none". This is the default behavior defined by Apple.
		// We have a safe guard to auto correct the test case information by keeping track of the active test case
		testListener.testCaseFinished("none", "none", nskeyedarchiver.XCActivityRecord{
			Finish:       nskeyedarchiver.NSDate{},
			Start:        nskeyedarchiver.NSDate{},
			Title:        "test",
			UUID:         nskeyedarchiver.NSUUID{},
			ActivityType: "userDefined",
			Attachments:  attachments,
		})
		testListener.testCaseDidFinishForTest("mysuite", "mymethod2", "failed", 1.0)

		// Suite end
		testListener.testSuiteFinished("mysuite", "2024-01-16 15:36:44 +0000", 0, 0, 0, 0, 0, 0, 1.0, 1.0)

		assert.Equal(t, 2, len(testListener.TestSuites[0].TestCases), "TestCase must be appended to list of test cases")
		assert.Equal(t, 0, len(testListener.TestSuites[0].TestCases[0].Attachments), "First test must have 0 attachments")
		assert.Equal(t, 1, len(testListener.TestSuites[0].TestCases[1].Attachments), "Second test must have 1 attachment")

		path := testListener.TestSuites[0].TestCases[1].Attachments[0].Path
		attachment, err := os.ReadFile(path)
		assert.NoError(t, err)
		defer os.RemoveAll(path)

		assert.Equal(t, "test", string(attachment), "Attachment content should be put in a file")
	})

	t.Run("Check test case without suite initialization", func(t *testing.T) {
		testListener := NewTestListener(io.Discard, io.Discard, os.TempDir())

		// This should trigger the nil pointer dereference error if not handled properly
		// Call testCaseDidStartForClass without first calling testSuiteDidStart
		assert.NotPanics(t, func() {
			testListener.testCaseDidStartForClass("mysuite", "mymethod")
		})

		// Verify that a new suite was created automatically
		assert.Equal(t, 1, len(testListener.TestSuites), "A test suite should be created automatically")

		// Verify the test case was added to the newly created suite
		assert.Equal(t, 1, len(testListener.TestSuites[0].TestCases), "TestCase must be appended to list of test cases")
		assert.Equal(t, TestCase{
			ClassName:  "mysuite",
			MethodName: "mymethod",
		}, testListener.TestSuites[0].TestCases[0])
	})
}

type assertionWriter struct {
	hasBytes bool
}

func (w *assertionWriter) Write(p []byte) (n int, err error) {
	if len(p) > 0 {
		w.hasBytes = true
	}

	return len(p), nil
}

func TestFindTestSuite(t *testing.T) {
	t.Run("finds suite by exact name", func(t *testing.T) {
		listener := NewTestListener(io.Discard, io.Discard, os.TempDir())
		listener.testSuiteDidStart("ShowAlert", "2024-01-16 15:36:43 +0000")

		suite := listener.findTestSuite("ShowAlert")
		assert.NotNil(t, suite)
		assert.Equal(t, "ShowAlert", suite.Name)
	})

	t.Run("returns nil for class names that don't match suite", func(t *testing.T) {
		listener := NewTestListener(io.Discard, io.Discard, os.TempDir())
		listener.testSuiteDidStart("ShowAlert", "2024-01-16 15:36:43 +0000")

		suite := listener.findTestSuite("HelloButton|ShowAlert")
		assert.Nil(t, suite)
	})

	t.Run("returns nil for unrelated test names", func(t *testing.T) {
		listener := NewTestListener(io.Discard, io.Discard, os.TempDir())
		listener.testSuiteDidStart("ShowAlert", "2024-01-16 15:36:43 +0000")

		suite := listener.findTestSuite("SomeOtherTest")
		assert.Nil(t, suite)
	})

	t.Run("returns nil when no suite is running", func(t *testing.T) {
		listener := NewTestListener(io.Discard, io.Discard, os.TempDir())

		suite := listener.findTestSuite("ShowAlert")
		assert.Nil(t, suite)
	})
}

func TestTestCaseLookup(t *testing.T) {
	t.Run("finds test case in different class within same suite", func(t *testing.T) {
		listener := NewTestListener(io.Discard, io.Discard, os.TempDir())
		listener.testSuiteDidStart("ShowAlert", "2024-01-16 15:36:43 +0000")
		listener.testCaseDidStartForClass("HelloButton|ShowAlert", "GivenILaunchTheApp")

		listener.testCaseDidFinishForTest("HelloButton|ShowAlert", "GivenILaunchTheApp", "passed", 1.0)

		testCase := listener.runningTestSuite.TestCases[0]
		assert.Equal(t, TestCaseStatus("passed"), testCase.Status)
		assert.Equal(t, 1.0, testCase.Duration.Seconds())
	})

	t.Run("handles BDD scenario tests", func(t *testing.T) {
		listener := NewTestListener(io.Discard, io.Discard, os.TempDir())
		listener.testSuiteDidStart("ShowAlert", "2024-01-16 15:36:43 +0000")

		listener.testCaseDidStartForClass("HelloButton|ShowAlert", "GivenILaunchTheApp")
		listener.testCaseDidStartForClass("HelloButton|ShowAlert", "WhenITapTheHelloButton")
		listener.testCaseDidStartForClass("HelloButton|ShowAlert", "ThenISeeHelloWorldAlert")

		listener.testCaseDidFinishForTest("HelloButton|ShowAlert", "GivenILaunchTheApp", "passed", 1.0)
		listener.testCaseDidFinishForTest("HelloButton|ShowAlert", "WhenITapTheHelloButton", "passed", 2.0)
		listener.testCaseDidFinishForTest("HelloButton|ShowAlert", "ThenISeeHelloWorldAlert", "passed", 3.0)

		cases := listener.runningTestSuite.TestCases
		assert.Len(t, cases, 3)
		for _, testCase := range cases {
			assert.Equal(t, TestCaseStatus("passed"), testCase.Status)
			assert.Greater(t, testCase.Duration.Seconds(), 0.0)
		}
	})

	t.Run("works with unrelated class names in suite", func(t *testing.T) {
		listener := NewTestListener(io.Discard, io.Discard, os.TempDir())
		listener.testSuiteDidStart("WidgetExpanderTest", "2024-01-16 15:36:43 +0000")
		listener.testCaseDidStartForClass("MagicTest", "verifyBlablabla")

		listener.testCaseDidFinishForTest("MagicTest", "verifyBlablabla", "passed", 1.0)

		testCase := listener.runningTestSuite.TestCases[0]
		assert.Equal(t, TestCaseStatus("passed"), testCase.Status)
		assert.Equal(t, 1.0, testCase.Duration.Seconds())
	})

	t.Run("handles repeated test executions", func(t *testing.T) {
		listener := NewTestListener(io.Discard, io.Discard, os.TempDir())
		listener.testSuiteDidStart("WidgetExpanderTest", "2024-01-16 15:36:43 +0000")

		listener.testCaseDidStartForClass("MagicTest", "verifyBlablabla")
		listener.testCaseDidStartForClass("MagicTest", "verifyBlablabla")
		listener.testCaseDidStartForClass("MagicTest", "verifyBlablabla")

		listener.testCaseDidFinishForTest("MagicTest", "verifyBlablabla", "passed", 1.0)
		listener.testCaseDidFinishForTest("MagicTest", "verifyBlablabla", "passed", 2.0)
		listener.testCaseDidFinishForTest("MagicTest", "verifyBlablabla", "failed", 3.0)

		cases := listener.runningTestSuite.TestCases
		assert.Len(t, cases, 3)

		for _, testCase := range cases {
			assert.NotEqual(t, TestCaseStatus(""), testCase.Status)
			assert.Greater(t, testCase.Duration.Seconds(), 0.0)
		}
	})
}

func TestResultReturnsDeepSnapshot(t *testing.T) {
	listener := NewTestListener(io.Discard, io.Discard, t.TempDir())
	listener.stateMu.Lock()
	listener.TestSuites = []TestSuite{{
		Name: "original-suite",
		TestCases: []TestCase{{
			MethodName: "original-case",
			Attachments: []TestAttachment{{
				Name: "original-attachment",
			}},
		}},
	}}
	listener.stateMu.Unlock()

	snapshot, err := listener.Result()
	assert.NoError(t, err)
	snapshot[0].Name = "mutated-suite"
	snapshot[0].TestCases[0].MethodName = "mutated-case"
	snapshot[0].TestCases[0].Attachments[0].Name = "mutated-attachment"

	again, err := listener.Result()
	assert.NoError(t, err)
	assert.Equal(t, "original-suite", again[0].Name)
	assert.Equal(t, "original-case", again[0].TestCases[0].MethodName)
	assert.Equal(t, "original-attachment", again[0].TestCases[0].Attachments[0].Name)
}

func TestAttachmentWriteDoesNotHoldListenerStateLock(t *testing.T) {
	listener := NewTestListener(io.Discard, io.Discard, t.TempDir())
	listener.testSuiteDidStart("suite", "2024-01-16 15:36:43 +0000")
	listener.testCaseDidStartForClass("suite", "test")

	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	listener.writeAttachment = func(_ string, _ []byte) error {
		close(writeStarted)
		<-releaseWrite
		return nil
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		listener.testCaseFinished("suite", "test", nskeyedarchiver.XCActivityRecord{
			Title:        "activity",
			ActivityType: "type",
			Attachments: []nskeyedarchiver.XCTAttachment{{
				Name:    "attachment",
				Payload: []byte("payload"),
			}},
		})
	}()
	<-writeStarted

	resultReturned := make(chan struct{})
	go func() {
		defer close(resultReturned)
		_, _ = listener.Result()
	}()
	select {
	case <-resultReturned:
	case <-time.After(time.Second):
		close(releaseWrite)
		<-finished
		t.Fatal("Result blocked behind attachment filesystem I/O")
	}

	// Moving the running suite into completed results while the file write is in
	// progress must not lose or mis-attribute the attachment.
	listener.testSuiteFinished("suite", "2024-01-16 15:36:44 +0000", 1, 0, 0, 0, 0, 0, 0.01, 0.01)
	close(releaseWrite)
	<-finished
	suites, err := listener.Result()
	assert.NoError(t, err)
	if assert.Len(t, suites, 1) && assert.Len(t, suites[0].TestCases, 1) {
		assert.Len(t, suites[0].TestCases[0].Attachments, 1)
	}
}

type blockingReadCloser struct {
	readStarted chan struct{}
	closed      chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
}

func (r *blockingReadCloser) Read(_ []byte) (int, error) {
	r.startOnce.Do(func() { close(r.readStarted) })
	<-r.closed
	return 0, io.EOF
}

func (r *blockingReadCloser) Close() error {
	r.closeOnce.Do(func() { close(r.closed) })
	return nil
}

func TestStopTestRunnerOutputCopyClosesAndJoinsReader(t *testing.T) {
	src := &blockingReadCloser{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
	stop := startTestRunnerOutputCopy(io.Discard, src)
	<-src.readStarted

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		stop()
		stop()
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("stdout cleanup did not close and join the copy goroutine")
	}
}

func TestListenerConcurrentDTXEventsAndResultSnapshots(t *testing.T) {
	var logOutput bytes.Buffer
	var debugOutput bytes.Buffer
	listener := NewTestListener(&logOutput, &debugOutput, t.TempDir())

	const eventsPerReader = 100
	start := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(2)
	go func() {
		defer writers.Done()
		<-start
		for event := 0; event < eventsPerReader; event++ {
			suite := fmt.Sprintf("suite-%d", event)
			method := fmt.Sprintf("event-%d", event)
			listener.LogMessage("stdout")
			listener.testSuiteDidStart(suite, "2024-01-16 15:36:43 +0000")
			listener.testCaseDidStartForClass(suite, method)
			listener.testCaseDidFinishForTest(suite, method, "passed", 0.01)
			listener.testSuiteFinished(suite, "2024-01-16 15:36:44 +0000", 1, 0, 0, 0, 0, 0, 0.01, 0.01)
		}
	}()
	go func() {
		defer writers.Done()
		<-start
		for event := 0; event < eventsPerReader; event++ {
			listener.setError(fmt.Errorf("reader error %d", event))
			listener.LogMessage("log")
			listener.LogDebugMessage("debug")
		}
	}()

	snapshotsDone := make(chan struct{})
	go func() {
		defer close(snapshotsDone)
		<-start
		for snapshot := 0; snapshot < eventsPerReader; snapshot++ {
			suites, _ := listener.Result()
			if len(suites) > 0 {
				suites[0].Name = "detached"
			}
		}
	}()

	close(start)
	writers.Wait()
	<-snapshotsDone

	suites, err := listener.Result()
	assert.Error(t, err)
	assert.Len(t, suites, eventsPerReader)
}

func TestConcurrentFinishSignalsDoneOnce(t *testing.T) {
	listener := NewTestListener(io.Discard, io.Discard, t.TempDir())
	listener.testSuiteDidStart("suite", "2024-01-16 15:36:43 +0000")

	var finishers sync.WaitGroup
	for i := 0; i < 32; i++ {
		finishers.Add(1)
		go func(index int) {
			defer finishers.Done()
			if index%2 == 0 {
				listener.FinishWithError(fmt.Errorf("failure %d", index))
				return
			}
			listener.didFinishExecutingTestPlan()
		}(i)
	}
	finishers.Wait()

	select {
	case <-listener.Done():
	case <-time.After(time.Second):
		t.Fatal("listener was not marked done")
	}
	_, err := listener.Result()
	assert.Error(t, err)
}

func TestRunXCTestTargetsIsolatesLateCallbacksAndSharesWriterLock(t *testing.T) {
	var output bytes.Buffer
	listener := NewTestListener(&output, &output, t.TempDir())

	oldTargetReleased := make(chan struct{})
	oldTargetReady := make(chan struct{})
	startWrites := make(chan struct{})
	oldTargetDone := make(chan struct{})
	var targetListeners []*TestListener
	secondTargetWasFinishedByOldCallback := false
	call := 0
	run := func(_ context.Context, config TestConfig) ([]TestSuite, error) {
		call++
		targetListeners = append(targetListeners, config.Listener)
		if call == 1 {
			config.Listener.testSuiteDidStart("first", "2024-01-16 15:36:43 +0000")
			config.Listener.testSuiteFinished("first", "2024-01-16 15:36:44 +0000", 1, 0, 0, 0, 0, 0, 0.01, 0.01)
			go func(oldListener *TestListener) {
				defer close(oldTargetDone)
				<-oldTargetReleased
				oldListener.didFinishExecutingTestPlan()
				close(oldTargetReady)
				<-startWrites
				for i := 0; i < 10_000; i++ {
					oldListener.LogMessage("old")
				}
				oldListener.testSuiteDidStart("late-old", "2024-01-16 15:36:45 +0000")
				oldListener.testSuiteFinished("late-old", "2024-01-16 15:36:46 +0000", 1, 0, 0, 0, 0, 0, 0.01, 0.01)
			}(config.Listener)
			return config.Listener.Result()
		}

		close(oldTargetReleased)
		<-oldTargetReady
		close(startWrites)
		for i := 0; i < 10_000; i++ {
			config.Listener.LogDebugMessage("new")
		}
		<-oldTargetDone
		select {
		case <-config.Listener.Done():
			secondTargetWasFinishedByOldCallback = true
		default:
		}
		config.Listener.testSuiteDidStart("second", "2024-01-16 15:36:47 +0000")
		config.Listener.testSuiteFinished("second", "2024-01-16 15:36:48 +0000", 1, 0, 0, 0, 0, 0, 0.01, 0.01)
		return config.Listener.Result()
	}

	results, err := runXCTestTargets(context.Background(), []TestConfig{{}, {}}, listener, run)
	assert.NoError(t, err)
	assert.Len(t, targetListeners, 2)
	assert.NotSame(t, listener, targetListeners[0])
	assert.NotSame(t, listener, targetListeners[1])
	assert.NotSame(t, targetListeners[0], targetListeners[1])
	assert.Same(t, targetListeners[0].outputWriterMutex(), targetListeners[1].outputWriterMutex())
	assert.False(t, secondTargetWasFinishedByOldCallback)
	if assert.Len(t, results, 2) {
		assert.Equal(t, "first", results[0].Name)
		assert.Equal(t, "second", results[1].Name)
	}
}
