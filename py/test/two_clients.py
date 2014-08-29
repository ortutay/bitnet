from bitnet_client import BitnetClient

a = BitnetClient("ab")
b = BitnetClient("cd")

a.Send(b.PubKeyStr(), "some message")

def handle_new_messages(message):
    print "Handler got message:", message
print "Listening for messages at %s" % a.PubKeyStr()
a.Listen(handle_new_messages)

while True:
    pass

