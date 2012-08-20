class FSM(object):
    state = 'START'
    def state_START(self):
        return 'STOP'
    def run(self):
        while True:
            method = getattr(self, "state_" + self.state)
            self.state = method()
            if self.state == 'PAUSE':
                break
            if self.state == 'STOP':
                if hasattr(self, "state_STOP"):
                    self.state_STOP()
                break
            
