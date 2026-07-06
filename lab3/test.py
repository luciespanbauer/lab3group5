#This is just an example of a testcase
#Vulnerability Name - Authentication available
import socket
from SampleNetworkClient import authenticate

#def authenticate(p, pw) :
#    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
#    s.sendto(b"AUTH %s" % pw, ("127.0.0.1", p))
#    msg, addr = s.recvfrom(1024)
#    return msg.strip()

try:
    
    infPort = 23456
    incPort = 23457
    #x = SampleNetworkClient(23456,23457)
    incToken = authenticate(incPort,b"!Q#E%T&U8i6y4r2w")

    print(incToken)
	
    # SampleNetworkServer has authentication so the testcase will exit at this assertion.
    assert(incToken != None)
except Exception as ex:
    print (ex)
    assert(1 == 2)
