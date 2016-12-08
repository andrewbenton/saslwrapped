module saslwrapped.prop;

extern(C):

struct propval
{
    char *name;
    char **values;
    uint nvalues;
    uint valsize;
}

enum PROP_DEFAULT;

struct propctx;

propctx *prop_new(uint estimate);

int prop_dup(propctx *src, propctx **dst);

int prop_request(propctx *ctx, char **names);

propval *prop_get(propctx *ctx);

int prop_getnames(propctx *ctx, char **names, propval *vals);

void prop_clear(propctx *ctx, int requests);

void prop_erase(propctx *ctx, char *name);

void prop_dispose(propctx **ctx);

int prop_format(propctx *ctx, char *sep, int seplen, char *outbuf, uint outmax, uint *outlen);

int prop_set(propctx *ctx, char *name, char *value, int vallen);

int prop_setvals(propctx *ctx, char *name, char **values);
