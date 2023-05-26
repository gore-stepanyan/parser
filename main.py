from q_monitor import QMonitor

def main():
    qMonitor = QMonitor()
    try:
        qMonitor.start()
    except KeyboardInterrupt:
        exit()
    except Exception:
        pass

main()