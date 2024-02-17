package logger

import (
	"log"
	"os"
	"sync"
	"time"
)

type g2eeLogger struct {
	normalLogger *log.Logger
	errorLogger  *log.Logger
	debugLogger  *log.Logger

	normalLogFile *os.File
	errorLogFile  *os.File
	debugLogFile  *os.File

	LogType_Normal string
	LogType_Error  string
	LogType_Debug  string

	mutex sync.Mutex
}

func New() *g2eeLogger {
	logger := &g2eeLogger{
		LogType_Normal: "normal",
		LogType_Error:  "error",
		LogType_Debug:  "debug",
	}
	logger.rotateLogFiles()
	return logger
}

func (l *g2eeLogger) Log(logType string, msg string) {
	if logType == "" {
		return
	}

	switch logType {
	case l.LogType_Normal:
		l.Debug(msg)
	case l.LogType_Error:
		l.Error(msg)
	case l.LogType_Debug:
		l.Normal(msg)
	}
}

// rotateLogFiles 用于旋转日志文件并更新关联的记录器。
func (l *g2eeLogger) rotateLogFiles() {
	// 加锁以确保在旋转日志文件期间操作的原子性
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// 关闭当前存在的所有日志文件
	if l.normalLogFile != nil {
		l.normalLogFile.Close()
	}
	if l.errorLogFile != nil {
		l.errorLogFile.Close()
	}
	if l.debugLogFile != nil {
		l.debugLogFile.Close()
	}

	// 获取当前时间，用于生成新的日志文件名
	t := time.Now()
	normalFileName := l.getLogFileName(l.LogType_Normal, t)
	errorFileName := l.getLogFileName(l.LogType_Error, t)
	debugFileName := l.getLogFileName(l.LogType_Debug, t)

	var err error
	// 打开或创建新的普通日志文件，并设置为追加写入模式
	l.normalLogFile, err = os.OpenFile(normalFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("打开普通日志文件时出错: %v", err)
	}
	// 同样处理错误日志文件
	l.errorLogFile, err = os.OpenFile(errorFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("打开错误日志文件时出错: %v", err)
	}
	// 同样处理调试日志文件
	l.debugLogFile, err = os.OpenFile(debugFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("打开调试日志文件时出错: %v", err)
	}

	// 更新各级别的日志记录器，使其指向新的日志文件，并设置输出格式
	l.normalLogger = log.New(l.normalLogFile, "NORMAL: ", log.Ldate|log.Ltime|log.Lshortfile)
	l.errorLogger = log.New(l.errorLogFile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	l.debugLogger = log.New(l.debugLogFile, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func (l *g2eeLogger) getLogFileName(logType string, t time.Time) string {
	return logType + "-" + t.Format("2006-01-02") + ".log"
}

func (l *g2eeLogger) Normal(msg string) {
	l.rotateIfNecessary()
	l.normalLogger.Println(msg)
}

func (l *g2eeLogger) Error(msg string) {
	l.rotateIfNecessary()
	l.errorLogger.Println(msg)
}

func (l *g2eeLogger) Debug(msg string) {
	l.rotateIfNecessary()
	l.debugLogger.Println(msg)
}

// rotateIfNecessary 是一个检查当前日志文件是否需要基于当前时间及文件修改时间进行轮转的方法。
func (l *g2eeLogger) rotateIfNecessary() {
	// 获取当前时间
	t := time.Now()

	// 获取标准日志文件的文件信息，如果出错则直接调用轮转方法
	fileInfo, err := l.normalLogFile.Stat()
	if err != nil {
		l.rotateLogFiles()
		return
	}

	// 检查当前日期与文件最后修改日期是否不同，若是，则执行日志文件轮转操作
	if t.Day() != fileInfo.ModTime().Day() {
		l.rotateLogFiles()
		return
	}
}
