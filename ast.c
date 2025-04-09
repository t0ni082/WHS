/*복사 동작 등 추정 불가, 구조만 유지

*/
void exit(int);

int main1() {
    return 0;
}

int main() {
    return main1();
}

void error() {
    exit(1);
}

char* my_realloc(char* old, int oldlen, int newlen) {
    char* new;
    int i;
    while () {
        
    }
    return new;
}

void takechar() {
    // getchar 함수 호출
}

void get_token() {
    // if 조건문 7개 존재
    if () {
    }
}

int peek(char* s) {
    return 0;
}

int accept(char* s) {
    if () {
    }
    return 0;
}

void expect(char* s) {
    if () {
    }
}

void save_int(char* p, int n) {
    // 할당 구문 존재
}

int load_int(char* p) {
    return 0;
}

void emit(int n, char* s) {
    if () {
    }
}

void be_push() {
}

void be_pop(int n) {
}

int sym_lookup(char* s) {
    if () {
    }
    return 0;
}

void sym_declare(char* s, int type, int value) {
    if () {
    }
}

int sym_declare_global(char* s) {
    return 0;
}

void sym_define_global(int current_symbol) {
    if () {
    }
}

void sym_get_value(char* s) {
    if () {
    }
    if () {
    }
    if () {
    }
    if () {
    }
    if () {
    }
}

void be_start() {
}

void be_finish() {
}

void promote(int type) {
    if () {
    }
    if () {
    }
}

int primary_expr() {
    if () {
    }
    return 0;
}

void binary1(int type) {
}

int binary2(int type, int n, char* s) {
    return 0;
}

int postfix_expr() {
    if () {
    }
    return 0;
}

int additive_expr() {
    if () {
    }
    return 0;
}

int shift_expr() {
    if () {
    }
    return 0;
}

int relational_expr() {
    return 0;
}

int equality_expr() {
    if () {
    }
    return 0;
}

int bitwise_and_expr() {
    return 0;
}

int bitwise_or_expr() {
    return 0;
}

int expression() {
    if () {
    }
    return 0;
}

void type_name() {
}

void statement() {
    if () {
    }
}

void program() {
    while () {
    }
}
