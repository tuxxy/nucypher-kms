from txjsonrpc.web import jsonrpc


class NuCypherRPC(jsonrpc.JSONRPC):
    """
    RPC root for NuCypher functions

    TODO: Do we need this? What should go here?
    """
    addSlash = True


class AliceRPC(jsonrpc.JSONRPC):
    """
    RPC methods for Alice API
    """
    pass


class BobRPC(jsonrpc.JSONRPC):
    """
    RPC methods for Bob API
    """
    pass
