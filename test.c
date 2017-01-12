#include <stdio.h>
#include <stdlib.h>

int fib(int n) {
	if (n == 0) return 1;
	if (n == 1) return 1;
	else return fib(n - 1) + fib(n - 2);
}

int get_n(char *str) {
	char buf[10];

	if (str == NULL) {
		printf(">> ");
		fgets(buf, sizeof(buf), stdin);
		return atoi(buf);
	} else return atoi(str);
}

int main(int argc, char **argv) {
	int n;

	if (argc == 2) n = get_n(argv[1]);
	else n = get_n(NULL);

	printf("%d\n", fib(n));

	return 0;
}