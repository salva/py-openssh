class SSHException(Exception):
    pass

class SSHPermissionDeniedException(SSHException):
    pass

class SSHFailureException(SSHException):
    pass

class SSHMuxProtocolException(SSHException):
    pass

class SSHMuxClosedException(SSHMuxProtocolException):
    pass

class SSHMuxTimeoutException(SSHMuxProtocolException, TimeoutError):
    pass
