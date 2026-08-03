package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

type Logger struct {
	mu         sync.Mutex
	level      Level
	out        io.Writer
	fileWriter io.WriteCloser
}

var globalLogger *Logger = NewLogger("info", "")

func NewLogger(levelStr string, logFile string) *Logger {
	l := &Logger{
		level: parseLevel(levelStr),
		out:   os.Stdout,
	}
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			l.fileWriter = f
			l.out = io.MultiWriter(os.Stdout, f)
		}
	}
	return l
}

func Init(levelStr string, logFile string) {
	globalLogger = NewLogger(levelStr, logFile)
}

func parseLevel(l string) Level {
	switch strings.ToLower(l) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

func IsDebug() bool {
	return globalLogger.level <= LevelDebug
}

func Debug(format string, args ...interface{}) {
	if globalLogger.level <= LevelDebug {
		logMsg("DEBUG", format, args...)
	}
}

func Info(format string, args ...interface{}) {
	if globalLogger.level <= LevelInfo {
		logMsg("INFO", format, args...)
	}
}

func Warn(format string, args ...interface{}) {
	if globalLogger.level <= LevelWarn {
		logMsg("WARN", format, args...)
	}
}

func Error(format string, args ...interface{}) {
	if globalLogger.level <= LevelError {
		logMsg("ERROR", format, args...)
	}
}

func logMsg(tag string, format string, args ...interface{}) {
	globalLogger.mu.Lock()
	defer globalLogger.mu.Unlock()
	timestamp := time.Now().Format("15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(globalLogger.out, "[%s] [%s] %s\n", timestamp, tag, msg)
}
