//
//  wish.c
//
//
//  Created by Chelsea Verheyen on 10/5/22.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>

void interactive_loop(void);
void batch(char *);
char * get_cmd(void);
char ** parse_cmd(char *);
void execute(char **);
void not_builtin(int, char **);
void my_exit(int, char**);
void my_cd(int, char**);
void my_path(int, char**);
int has_redirection(int, char**);
int if_statement(int, char **);
int get_returnval(char**);

char error_message[30] = "An error has occurred\n";
char **search_paths;
int search_path_len;

int main(int argc, char *argv[]) {
    
    search_paths = malloc(256 * sizeof(char*));
    search_paths[0] = "/bin";
    search_path_len = 1;
    
    if (argc == 1) {
        // interactive mode
        interactive_loop();
    } else if (argc > 1){
        // batch mode
        for (int i = 1; i < argc; i++) {
            batch(argv[i]);
        }
    }
    
    free(search_paths);
    
    return 0;
}

// read input from batch file and executes the commands
void batch(char * filename) {
    char *buf = NULL;
    size_t size = 0;
    FILE *file = fopen(filename, "r");
    if (!file) {
        write(STDERR_FILENO, error_message, strlen(error_message));
        exit(1);
        return;
    }
    ssize_t line = getline(&buf, &size, file);
    char **parsed_cmd;
    while (line >= 0) {
        // get rid of newline char
        if (buf[strlen(buf)-1] == '\n') {
            buf[strlen(buf)-1] = 0;
        }
        parsed_cmd = parse_cmd(buf);
        execute(parsed_cmd);
        line = getline(&buf, &size, file);
        free(parsed_cmd);
    }
    free(buf);
    buf = NULL;
    fclose(file);
}

// continuously prompt user, parse commands, and execute
void interactive_loop() {
    char *cmd;
    char **parsed_cmd;
    while(1) {
        printf("wish> ");
        cmd = get_cmd();
        parsed_cmd = parse_cmd(cmd);
        execute(parsed_cmd);
        free(cmd);
        free(parsed_cmd);
    }
}

// returns user input
char * get_cmd() {
    char *buf = NULL;
    size_t size = 0;
    getline(&buf, &size, stdin);
    // get rid of newline char
    if (buf[strlen(buf)-1] == '\n') {
        buf[strlen(buf)-1] = 0;
    }
    return buf;
}

// splits user input into a series of tokens separated by spaces
char ** parse_cmd(char *cmd) {
    int size = 256;
    char **tokens = malloc(size * sizeof(char*));
    char *token = strtok(cmd, " ");
    int i = 0;
    while (token != NULL) {
        // check if redirection operator > is part of another command token
        int redir_idx = -1;
        for (int j = 0; j < strlen(token); j++) {
            if (token[j] == '>' && redir_idx == -1) {
                redir_idx = j;
            }
        }
        if (redir_idx != -1 && strlen(token) > 1) {
            // redirection exists
            char *tok1 = malloc(redir_idx * sizeof(char));
            for (int j = 0; j < redir_idx; j++) {
                tok1[j] = token[j];
            }
            char *tok2 = ">";
            char *tok3 = malloc((strlen(token)-redir_idx) * sizeof(char));
            for (int j = redir_idx+1; j < strlen(token); j++) {
                tok3[j-(redir_idx+1)] = token[j];
            }
            tokens[i] = tok1; // command before >
            tokens[i+1] = tok2; // >
            tokens[i+2] = tok3; // command after >
            i += 3;
        } else {
            // no redirection, continue as normal
            tokens[i] = token;
            i++;
        }
        // reallocate if necessary
        if (i >= size) {
         size += 256;
         tokens = realloc(tokens, size * sizeof(char*));
        }
        token = strtok(NULL, " ");
     }
     tokens[i] = NULL;
     return tokens;
}

// takes the parsed command tokens and actually executes them
void execute(char ** cmd) {
    if (cmd[0] == NULL) {
        return;
    }
    int cmd_len;
    for (cmd_len = 0; cmd[cmd_len + 1]; cmd_len++);
    
    // determine if command is a conditional, built in, or not built-in
    int conditional = if_statement(cmd_len, cmd);
    if (conditional) {
        // execution handled by if_statement method
        return;
    } else if (!strcmp(cmd[0], "exit")) {
        my_exit(cmd_len, cmd);
    } else if (!strcmp(cmd[0], "cd")) {
        my_cd(cmd_len, cmd);
    } else if (!strcmp(cmd[0], "path")) {
        my_path(cmd_len, cmd);
    } else {
        not_builtin(cmd_len, cmd);
    }
}

// create process for command and run corresponding program if it exists
void not_builtin(int cmd_len, char **cmd) {
    int redir = has_redirection(cmd_len, cmd);
    if (redir == -1) {
        write(STDERR_FILENO, error_message, strlen(error_message));
        return;
    }
    
    int rc = fork();
    if (rc < 0) {
        // fork failed
        exit(1);
    } else if (rc == 0) {
        // child
        int success = 0;
        // look through search path for executables matching command
        for (int i = 0; i < search_path_len; i++) {
            char *path = strdup(search_paths[i]);
            strcat(strcat(path, "/"), cmd[0]);
            if (!access(path, X_OK)) {
                // found match
                success = 1;
                if (redir) {
                    // redirect output if necessary
                    int fd = open(cmd[redir+1], O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
                    dup2(fd, 1);
                    close(fd);
                    cmd[redir] = 0;
                }
                // execute command
                execv(path, cmd);
                break;
            }
        }
        if (!success) {
            // no match found
            write(STDERR_FILENO, error_message, strlen(error_message));
            exit(0);
        }
    } else {
        // parent
        int rc_wait = wait(NULL);
    }
}

// exit program
void my_exit(int argc, char** argv) {
    if (argc > 0) {
        write(STDERR_FILENO, error_message, strlen(error_message));
    } else {
        exit(0);
    }
}

// change directories
void my_cd(int argc, char** argv) {
    if (argc != 1) {
        write(STDERR_FILENO, error_message, strlen(error_message));
    } else {
        if(chdir(argv[1])) {
            write(STDERR_FILENO, error_message, strlen(error_message));
        };
    }
}

// adds each argument to the search path of the shell (always overwrites old path)
void my_path(int argc, char** argv) {
    search_path_len = argc;
    for (int i = 0; i < argc; i++) {
        search_paths[i] = strdup(argv[i+1]);
    }
    search_paths[argc] = NULL;
}

// checks if command has redirection (marked by '>')
// returns index of '>' character if it exists, 0 if it doesn't, -1 if there's an error
int has_redirection(int cmd_len, char** cmd) {
    int has_arrow = 0;
    int arrow_idx;
    for (int i = 0; i < cmd_len + 1; i++) {
        if (!strcmp(cmd[i], ">")) {
            has_arrow += 1;
            arrow_idx = i;
        }
    }
    if (has_arrow == 0) {
        // no redirection
        return 0;
    } else if (has_arrow > 1 || arrow_idx != (cmd_len - 1)) {
        // error with redirection
        return -1;
    } else {
        return arrow_idx;
    }
}

// handles if statement: execute a command if condition evaluates to true
// format: if <cmd> <comparison_operator> <constant> then <cmd> fi
// return 0 for no if statement, 1 for success, and -1 for error
int if_statement(int cmd_len, char **cmd) {
    if (!strcmp(cmd[0], "if") && !strcmp(cmd[cmd_len], "fi")) {
        int then_idx = -1;
        for (int i = 0; i < cmd_len; i++) {
            if (!strcmp(cmd[i], "then")) {
                then_idx = i;
                break;
            }
        }
        if (then_idx == -1) {
            write(STDERR_FILENO, error_message, strlen(error_message));
            return -1;
        }
        
        // separate into pieces
        char *comparison = cmd[then_idx-2];
        char *constant = cmd[then_idx-1];
        char **cmd2 = malloc(256 * sizeof(char *));
        for (int i = 1; i < then_idx-2; i++) {
            cmd2[i-1] = strdup(cmd[i]);
        }
        char **cmd3 = malloc(256 * sizeof(char *));
        for (int i = then_idx+1; i < cmd_len; i++) {
            cmd3[i-(then_idx+1)] = strdup(cmd[i]);
        }
        
        int result = get_returnval(cmd2);
        
        if (!strcmp(comparison, "==")) {
            if (result == atoi(constant)) {
                // if statement is true, execute command
                execute(cmd3);
            }
        } else if (!strcmp(comparison, "!=")) {
            if (result != atoi(constant)) {
                // if statement is true, execute command
                execute(cmd3);
            }
        } else {
            write(STDERR_FILENO, error_message, strlen(error_message));
        }
        return 1;
    }
    
    return 0;
}

// create process for command, executes, and returns the return value of it
int get_returnval(char **cmd) {
    int retval;
    int rc_wait;
    int rc = fork();
    if (rc < 0) {
        // fork failed
        exit(1);
    } else if (rc == 0) {
        // child
        int success = 0;
        for (int i = 0; i < search_path_len; i++) {
            char *path = strdup(search_paths[i]);
            strcat(strcat(path, "/"), cmd[0]);
            if (!access(path, X_OK)) {
                success = 1;
                execv(path, cmd);
                break;
            }
        }
        if (!success) {
            exit(0);
        }
    } else {
        // parent
        rc_wait = wait(&retval);
    }
    return WEXITSTATUS(retval);
}

