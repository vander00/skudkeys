package logging

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu   sync.Mutex
	out  io.Writer
	file *os.File
}

func New(out io.Writer) *Logger {
	return &Logger{out: out, file: nil}
}

func (l *Logger) WithFile(file *os.File) (*Logger, error) {
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("logger file '%s' is a directory", file.Name())
	}

	l.mu.Lock()
	out := l.out
	l.mu.Unlock()

	return &Logger{
		out:  out,
		file: file,
	}, nil
}

func (l *Logger) logf(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().Format("2006-01-02 15:04:05")
	stringToWrite := fmt.Sprintf("%s [%s] %s\n", ts, level, fmt.Sprintf(format, args...))

	_, _ = fmt.Fprint(l.out, stringToWrite)
	if l.file == nil {
		return
	}
	_, _ = l.file.WriteString(stringToWrite)
}

func (l *Logger) Info(format string, args ...any)  { l.logf("INFO", format, args...) }
func (l *Logger) Warn(format string, args ...any)  { l.logf("WARN", format, args...) }
func (l *Logger) Error(format string, args ...any) { l.logf("ERROR", format, args...) }
