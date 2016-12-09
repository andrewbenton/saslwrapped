module saslwrapped.client;

import core.stdc.config;
import core.stdc.stdlib;

import std.conv;
import std.format : format;
import std.stdio;
import std.string;

import saslwrapped.sasl;

/**
    This client implementation is pretty much a direct rip-off of
    https://github.com/cloudera/python-sasl/blob/master/sasl/saslwrapper.h
*/

extern(C) int cbName(void *context, int id, char **result, uint *len) nothrow
{
    Client cli = cast(Client)context;

    if(id == SASL_CB_USER || (id == SASL_CB_AUTHNAME && cli.authName.empty))
        *result = cast(char*)cli.userName.toStringz;
    else
        *result = cast(char*)cli.authName.toStringz;

    return SASL_OK;
}

extern(C) int cbPassword(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret) nothrow
{
    Client cli = cast(Client)context;
    size_t length = cli.password.length;

    if(id == SASL_CB_PASS)
    {
        import core.stdc.string;
        cli.secret.len = length;
        memcpy(cli.secret.data, cast(char*)cli.password.toStringz, length);
    }
    else
    {
        cli.secret.len = 0;
    }

    *psecret = cli.secret;

    return SASL_OK;
}

class Client
{
private:
    void addCallback(c_ulong id, void *proc)
    {
        callbacks[this.cbIndex].id = id;
        callbacks[this.cbIndex].proc = cast(sasl_callback_func)proc;
        callbacks[this.cbIndex].context = cast(void*)this;
        this.cbIndex++;
    }

    void lastCallback()
    {
        this.addCallback(SASL_CB_LIST_END, null);
    }

    void setError(string context, int code, string text = "", string text2 = "")
    {
        string errorText;
        if(text.empty)
        {
            if(this.conn)
                errorText = sasl_errdetail(this.conn).fromStringz.to!string;
            else
                errorText = sasl_errstring(code, null, null).fromStringz.to!string;
        }
        else
        {
            errorText = text;
        }

        if(text2.empty)
            this.error = "Error in %s (%s) %s".format(context, code, errorText);
        else
            this.error = "Error in %s (%s) %s - %s".format(context, code, errorText, text2);
    }

    void interact(sasl_interact_t *prompt)
    {
        string output;
        char *input;

        if(prompt.id == SASL_CB_PASS)
        {
            string ppt = prompt.prompt.fromStringz.to!string;
            ppt ~= ": ";
            version(linux)
            {
                import core.sys.linux.unistd;
                char *pass = core.sys.linux.unistd.getpass(cast(char*)ppt.toStringz);
            }
            else
            {
                stdout.write(ppt);
                stdout.flush;
                char *pass = readln;
            }
            output = pass.fromStringz.to!string;
        }
        else
        {
            import std.stdio;
            stdout.write(prompt.prompt.fromStringz.to!string);
            if(prompt.defresult)
                stdout.writef(" [%s]", prompt.defresult.fromStringz.to!string);
            stdout.write(": ");
            stdout.flush;
            output = readln;
        }

        prompt.result = cast(char*)output.ptr;
        prompt.len = cast(uint)output.length;
    }

    //__gshared bool initialized = false;
    shared static initialized = false; //this allows me to use atomics on the initialization

    sasl_conn_t *conn;
    sasl_callback_t[8] callbacks;
    int cbIndex;
    string error;
    string serviceName;
    string userName;
    string authName;
    string password;
    string hostName;
    string externalUserName;
    uint maxBufSize;
    uint minSsf;
    uint maxSsf;
    uint externalSsf;
    sasl_secret_t *secret;

public:
    this()
    {
        this.conn = null;
        this.cbIndex = 0;
        this.maxBufSize = 65535;
        this.minSsf = 0;
        this.maxSsf = 65535;
        this.externalSsf = 0;
        this.secret = null;
    }

    ~this()
    {
        if(this.conn)
        {
            sasl_dispose(&(this.conn));
            this.conn = null;
        }
    }

    bool setAttr(string key, string value)
    {
        if(key == "service")
            this.serviceName = value;
        else if(key == "username")
            this.userName = value;
        else if(key == "authname")
            this.authName = value;
        else if(key == "password")
        {
            this.password = value;
            free(this.secret);
            this.secret = cast(sasl_secret_t*)malloc(sasl_secret_t.sizeof + this.password.length);
        }
        else if(key == "host")
            this.hostName = value;
        else if(key == "externaluser")
            this.externalUserName = value;
        else
        {
            this.setError("setAttr", -1, "Unknown string attribute name", key);
            return false;
        }

        return true;
    }

    bool setAttr(string key, uint value)
    {
        if(key == "minssf")
            this.minSsf = value;
        else if(key == "maxssf")
            this.maxSsf = value;
        else if(key == "externalssf")
            this.externalSsf = value;
        else if(key == "maxbufsize")
            this.maxBufSize = value;
        else
        {
            this.setError("setAttr", -1, "Unknown integer attribute name", key);
            return false;
        }

        return true;
    }

    bool init()
    {
        int result;

        import core.atomic : atomicLoad, atomicStore;

        if(!atomicLoad(Client.initialized))
        {
            atomicStore(Client.initialized, true);
            result = sasl_client_init(null);

            if(result != SASL_OK)
            {
                this.setError("sasl_client_init", result, sasl_errstring(result, null, null).fromStringz.to!string);
                return false;
            }
        }

        this.addCallback(SASL_CB_GETREALM, null);

        if(!this.userName.empty)
        {
            this.addCallback(SASL_CB_USER, cast(void*)&cbName);
            this.addCallback(SASL_CB_AUTHNAME, cast(void*)&cbName);

            if(!this.password.empty)
                this.addCallback(SASL_CB_PASS, cast(void*)&cbPassword);
            else
                this.addCallback(SASL_CB_PASS, null);
        }

        this.lastCallback();

        uint flags = 0;

        if(!this.authName.empty && this.authName != this.userName)
            flags |= SASL_NEED_PROXY;

        result = sasl_client_new(
                cast(char*)this.serviceName.toStringz,
                cast(char*)this.hostName.toStringz,
                null,
                null,
                callbacks.ptr,
                flags,
                &(this.conn));

        if(result != SASL_OK)
        {
            this.setError("sasl_client_new", result, sasl_errstring(result, null, null).fromStringz.to!string);
            return false;
        }

        sasl_security_properties_t secprops;

        secprops.min_ssf = this.minSsf;
        secprops.max_ssf = this.maxSsf;
        secprops.maxbufsize = this.maxBufSize;
        secprops.property_names = null;
        secprops.property_values = null;
        secprops.security_flags = 0;

        result = sasl_setprop(this.conn, SASL_SEC_PROPS, &secprops);
        if(result != SASL_OK)
        {
            this.setError("sasl_setprop(SASL_SEC_PROPS)", result);
            sasl_dispose(&(this.conn));
            this.conn = null;
            return false;
        }

        if(!this.externalUserName.empty)
        {
            result = sasl_setprop(conn, SASL_AUTH_EXTERNAL, cast(char*)this.externalUserName.toStringz);
            if(result != SASL_OK)
            {
                this.setError("sasl_setprop(SASL_AUTH_EXTERNAL)", result);
                sasl_dispose(&(this.conn));
                this.conn = null;
                return false;
            }

            result = sasl_setprop(conn, SASL_SSF_EXTERNAL, &(this.externalSsf));
            if(result != SASL_OK)
            {
                this.setError("sasl_setprop(SASL_SSF_EXTERNAL)", result);
                sasl_dispose(&(this.conn));
                this.conn = null;
                return false;
            }
        }

        return true;
    }

    bool start(string mechList, ref string chosen, ref string initialResponse)
    {
        int result;
        sasl_interact_t *prompt = null;
        char *resp;
        char *mech;
        uint len;

        do
        {
            result = sasl_client_start(conn, cast(char*)mechList.toStringz, &prompt, &resp, &len, &mech);
            if(result == SASL_INTERACT)
                this.interact(prompt);
        }
        while(result == SASL_INTERACT);

        if(result != SASL_OK && result != SASL_CONTINUE)
        {
            this.setError("sasl_client_start", result);
            return false;
        }

        chosen = mech.fromStringz.to!string;
        initialResponse = resp[0 .. len].to!string;

        return true;
    }

    bool step(string challenge, ref string response)
    {
        int result;
        sasl_interact_t* prompt = null;
        char *resp;
        uint len;

        do
        {
            result = sasl_client_step(this.conn, cast(char*)challenge.toStringz, cast(uint)challenge.length, &prompt, &resp, &len);
            if(result == SASL_INTERACT)
                this.interact(prompt);
        }
        while(result == SASL_INTERACT);

        if(result != SASL_OK && result != SASL_CONTINUE)
        {
            this.setError("sasl_client_step", result);
            return false;
        }

        response = resp[0 .. len].to!string;
        return true;
    }

    bool encode(string clearText, ref string cipherText)
    {
        char *output;
        uint outlen;

        int result = sasl_encode(conn, cast(char*)clearText.toStringz, cast(uint)clearText.length, &output, &outlen);
        if(result != SASL_OK)
        {
            this.setError("sasl_encode", result);
            return false;
        }

        cipherText = output[0 .. outlen].to!string;
        return true;
    }

    bool decode(string cipherText, ref string clearText)
    {
        import std.array : appender, Appender;

        char *input = cast(char*)cipherText.toStringz;
        uint inlen = cast(uint)cipherText.length;
        uint remaining = inlen;
        char *cursor = input;
        char *output;
        uint outlen;

        Appender!string ctb = appender!string;
        scope(exit)
            clearText = ctb.data;

        while(remaining > 0)
        {
            uint segmentLen = (remaining < maxBufSize) ? remaining : maxBufSize;
            int result = sasl_decode(this.conn, cursor, segmentLen, &output, &outlen);
            if(result != SASL_OK)
            {
                this.setError("sasl_decode", result);
                return false;
            }

            ctb ~= output[0 .. outlen].to!string;
            cursor += segmentLen;
            remaining -= segmentLen;
        }

        return true;
    }

    bool getUserId(ref string userId)
    {
        int result;
        char *operName;

        result = sasl_getprop(this.conn, SASL_USERNAME, cast(void**)&operName);
        if(result != SASL_OK)
        {
            this.setError("sasl_getprop(SASL_USERNAME)", result);
            return false;
        }

        userId = operName.fromStringz.to!string;
        return true;
    }

    bool getSSF(ref int ssf)
    {
        int *_ssf = null;

        scope(exit)
            if(_ssf)
                ssf = *_ssf;

        int result = sasl_getprop(this.conn, SASL_SSF, cast(void**)&_ssf);
        if(result != SASL_OK)
        {
            this.setError("sasl_getprop(SASL_SSF)", result);
            return false;
        }

        return true;
    }

    void getError(ref string error)
    {
        error = this.error;
        this.error = null;
    }
}
