import saslwrapped;

import std.stdio;

int main(string[] args)
{
    Client client = new Client;

    writeln("created client");

    client.setAttr("username", "my_user");
    client.setAttr("password", "my_pass");

    client.init();

    writeln("initialized client");

    string chosen, initialResponse;

    if(!client.start("DIGEST-MD5", chosen, initialResponse))
    {
        writeln("Failed to start client");
        string error;
        client.getError(error);
        writefln(error);
        return -1;
    }

    writeln("started client");

    writefln("SASL: ");
    writefln("\tchosen: %s", chosen);
    writefln("\tinitialResponse: %s", initialResponse);

    /* run stepping here */

    foreach(msg; ["one", "two", "three", "four"])
    {
        import std.format : format;
        string clear = "My message is: %s".format(msg);
        string cypher;
        if(!client.encode(clear, cypher))
            writefln("ENCODING FAILED");

        writefln("encoding: \"%s\"", clear);
        writefln("encoded : \"%s\"", cypher);
    }

    return 0;
}
