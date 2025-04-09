#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

typedef struct {
    char *name;
    char *return_type;
    int param_count;
    char **param_types;
    char **param_names;
    int if_count;
    int is_definition;
} FunctionInfo;

static FunctionInfo *func = NULL;
static int function_count = 0;

char *get_type(cJSON *typeNode);
void count_ifs(cJSON *node, FunctionInfo *fi);
void handle_funcdef(cJSON *node);
void handle_funcdecl(cJSON *node);
void onion(cJSON *node);
int has_funcdef(const char *name);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s ast.json\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen"); return 1; }
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *data = malloc(len + 1);
    fread(data, 1, len, fp);
    data[len] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(data);
    if (!root) {
        fprintf(stderr, "Parse error: %s\n", cJSON_GetErrorPtr());
        free(data);
        return 1;
    }

    onion(root);

    int printed = 0;
    printf("\n======= Function Analyze Results =======\n");
    for (int i = 0; i < function_count; ++i) {
        FunctionInfo *fi = &func[i];
        if (!fi->is_definition && has_funcdef(fi->name)) continue;

        printf("\nFunction <%s>%s\n", fi->name, fi->is_definition ? "" : " (Decl only)");
        printf("  Return type  : %s\n", fi->return_type);
        printf("  Parameters   : %d\n", fi->param_count);
        for (int j = 0; j < fi->param_count; ++j)
            printf("    - %s %s\n", fi->param_types[j], fi->param_names[j]);
        if (fi->is_definition)
            printf("  Number of if : %d\n", fi->if_count);

        printed++;
    }
    printf("\n========================================\n");
    printf("    Total number of functions: %d\n", printed);
    printf("========================================\n\n");

    cJSON_Delete(root);
    free(data);
    return 0;
}

void onion(cJSON *node) {
    if (!node) return;
    if (node->type == cJSON_Object) {
        const char *ntype = cJSON_GetObjectItem(node, "_nodetype")->valuestring;
        if (strcmp(ntype, "FuncDef") == 0) handle_funcdef(node);
        else if (strcmp(ntype, "Decl") == 0) {
            cJSON *type = cJSON_GetObjectItem(node, "type");
            if (type && strcmp(cJSON_GetObjectItem(type, "_nodetype")->valuestring, "FuncDecl") == 0)
                handle_funcdecl(node);
        }
        cJSON *child = NULL;
        cJSON_ArrayForEach(child, node)
            if (child->type == cJSON_Object || child->type == cJSON_Array)
                onion(child);
    } else if (node->type == cJSON_Array) {
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, node)
            onion(item);
    }
}

void handle_funcdef(cJSON *node) {
    cJSON *decl = cJSON_GetObjectItem(node, "decl");
    char *name = strdup(cJSON_GetObjectItem(decl, "name")->valuestring);

    cJSON *type = cJSON_GetObjectItem(decl, "type");
    char *rtype = get_type(cJSON_GetObjectItem(type, "type"));

    char **ptypes = NULL, **pnames = NULL;
    int param_count = 0;
    cJSON *args = cJSON_GetObjectItem(type, "args");
    if (args) {
        cJSON *params = cJSON_GetObjectItem(args, "params");
        param_count = cJSON_GetArraySize(params);
        ptypes = malloc(sizeof(char*) * param_count);
        pnames = malloc(sizeof(char*) * param_count);
        for (int i = 0; i < param_count; ++i) {
            cJSON *p = cJSON_GetArrayItem(params, i);
            ptypes[i] = get_type(cJSON_GetObjectItem(p, "type"));
            pnames[i] = strdup(cJSON_GetObjectItem(p, "name")->valuestring);
        }
    }

    func = realloc(func, sizeof(FunctionInfo) * (function_count + 1));
    FunctionInfo *fi = &func[function_count++];
    fi->name = name;
    fi->return_type = rtype;
    fi->param_count = param_count;
    fi->param_types = ptypes;
    fi->param_names = pnames;
    fi->if_count = 0;
    fi->is_definition = 1;

    count_ifs(cJSON_GetObjectItem(node, "body"), fi);
}

void handle_funcdecl(cJSON *node) {
    char *name = strdup(cJSON_GetObjectItem(node, "name")->valuestring);
    if (has_funcdef(name)) { free(name); return; }

    cJSON *type = cJSON_GetObjectItem(node, "type");
    char *rtype = get_type(cJSON_GetObjectItem(type, "type"));

    char **ptypes = NULL, **pnames = NULL;
    int param_count = 0;
    cJSON *args = cJSON_GetObjectItem(type, "args");
    if (args) {
        cJSON *params = cJSON_GetObjectItem(args, "params");
        param_count = cJSON_GetArraySize(params);
        ptypes = malloc(sizeof(char*) * param_count);
        pnames = malloc(sizeof(char*) * param_count);
        for (int i = 0; i < param_count; ++i) {
            cJSON *p = cJSON_GetArrayItem(params, i);
            ptypes[i] = get_type(cJSON_GetObjectItem(p, "type"));
            pnames[i] = strdup(cJSON_GetObjectItem(p, "name")->valuestring);
        }
    }

    func = realloc(func, sizeof(FunctionInfo) * (function_count + 1));
    FunctionInfo *fi = &func[function_count++];
    fi->name = name;
    fi->return_type = rtype;
    fi->param_count = param_count;
    fi->param_types = ptypes;
    fi->param_names = pnames;
    fi->if_count = 0;
    fi->is_definition = 0;
}

int has_funcdef(const char *name) {
    for (int i = 0; i < function_count; ++i)
        if (strcmp(func[i].name, name) == 0 && func [i].is_definition)
            return 1;
    return 0;
}

void count_ifs(cJSON *node, FunctionInfo *fi) {
    if (!node) return;
    if (node->type == cJSON_Object) {
        cJSON *nt = cJSON_GetObjectItem(node, "_nodetype");
        if (nt && strcmp(nt->valuestring, "If") == 0)
            fi->if_count++;
        cJSON *child = NULL;
        cJSON_ArrayForEach(child, node)
            if (child->type == cJSON_Object || child->type == cJSON_Array)
                count_ifs(child, fi);
    } else if (node->type == cJSON_Array) {
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, node)
            count_ifs(item, fi);
    }
}

char *get_type(cJSON *typeNode) {
    if (!typeNode) return strdup("unknown");
    const char *nt = cJSON_GetObjectItem(typeNode, "_nodetype")->valuestring;

    if (strcmp(nt, "PtrDecl") == 0) {
        char *base = get_type(cJSON_GetObjectItem(typeNode, "type"));
        char *res = malloc(strlen(base) + 2);
        sprintf(res, "%s*", base);
        free(base);
        return res;
    }
    if (strcmp(nt, "TypeDecl") == 0)
        return get_type(cJSON_GetObjectItem(typeNode, "type"));
    if (strcmp(nt, "IdentifierType") == 0) {
        cJSON *names = cJSON_GetObjectItem(typeNode, "names");
        return strdup(cJSON_GetArrayItem(names, 0)->valuestring);
    }
    return strdup("unknown");
}
