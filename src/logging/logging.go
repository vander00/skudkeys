package logging

import (
	"fmt"
	"io"
	"sync"
	"time"
)

type Logger struct {
	mu  sync.Mutex
	out io.Writer
}

func New(out io.Writer) *Logger { return &Logger{out: out} }

func (l *Logger) logf(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(l.out, "%s [%s] %s\n", ts, level, fmt.Sprintf(format, args...))
}

func (l *Logger) Info(format string, args ...any)  { l.logf("INFO", format, args...) }
func (l *Logger) Warn(format string, args ...any)  { l.logf("WARN", format, args...) }
func (l *Logger) Error(format string, args ...any) { l.logf("ERROR", format, args...) }
