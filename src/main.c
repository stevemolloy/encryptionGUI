#include <assert.h>
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "raylib.h"

#define GCRY_CIPHER GCRY_CIPHER_AES256
#define GCRY_MODE GCRY_CIPHER_MODE_CBC

#define KEY_LENGTH 32 // 256 bits
#define IV_LENGTH 16  // 128 bits

#define MAX_SALT_CHARS 24
#define MAX_PASSWD_CHARS 12

#define INITIAL_WIDTH 900
#define INITIAL_HEIGHT 600
#define FONTSIZE 30
#define BACKGROUND_COLOUR CLITERAL(Color){ 0x20, 0x20, 0x20, 0xFF }

void handle_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

void encrypt_file(char *input_filename, char *salt, char *password) {
    gcry_cipher_hd_t handle;
    gcry_error_t err;

    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file) handle_error("Failed to open input file");

    bool filename_has_extension = false;
    size_t input_filename_len = strlen(input_filename);
    for (size_t i=0; i<input_filename_len; i++) {
      if (input_filename[i] == '.' && i<input_filename_len - 1) {
        filename_has_extension = true;
      }
    }

    if (filename_has_extension) {
      char *cursor = input_filename;
      while (*cursor != '.') cursor++;
      *cursor = '\0';
    }
    input_filename = realloc(input_filename, strlen(input_filename) + 4);
    strcat(input_filename, ".enc");

    FILE *output_file = fopen(input_filename, "wb");
    if (!output_file) {
        fclose(input_file);
        handle_error("Failed to open output file");
    }

    // Derive a key from the password using a key derivation function (KDF)
    unsigned char key[KEY_LENGTH];
    err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, 4, 4096, KEY_LENGTH, key);
    if (err) handle_error("Key derivation failed");

    // Generate a random initialization vector (IV)
    unsigned char iv[IV_LENGTH];
    gcry_randomize(iv, IV_LENGTH, GCRY_STRONG_RANDOM);

    // Write the IV to the output file
    fwrite(iv, 1, IV_LENGTH, output_file);

    // Initialize the cipher handle
    err = gcry_cipher_open(&handle, GCRY_CIPHER, GCRY_MODE, 0);
    if (err) handle_error("Cipher initialization failed");

    // Set the key for the cipher handle
    err = gcry_cipher_setkey(handle, key, KEY_LENGTH);
    if (err) {
        gcry_cipher_close(handle);
        handle_error("Failed to set cipher key");
    }

    // Set the IV for the cipher handle
    err = gcry_cipher_setiv(handle, iv, IV_LENGTH);
    if (err) {
        gcry_cipher_close(handle);
        handle_error("Failed to set cipher IV");
    }

    // Encrypt the file content block by block
    size_t block_size = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    unsigned char *buffer = malloc(block_size);

    while (1) {
        size_t bytes_read = fread(buffer, 1, block_size, input_file);
        if (bytes_read == 0) {
            break; // End of file
        }

        // Pad the last block if needed
        if (bytes_read < block_size) {
            memset(buffer + bytes_read, block_size - bytes_read, block_size - bytes_read);
        }

        // Encrypt the block
        err = gcry_cipher_encrypt(handle, buffer, block_size, NULL, 0);
        if (err) {
            free(buffer);
            gcry_cipher_close(handle);
            fclose(input_file);
            fclose(output_file);
            handle_error("Encryption failed");
        }

        // Write the encrypted block to the output file
        fwrite(buffer, 1, block_size, output_file);
    }

    free(buffer);
    gcry_cipher_close(handle);
    fclose(input_file);
    fclose(output_file);

    printf("Encryption complete.\n");
}

typedef enum {
  WAITING_FOR_FILE,
  WAITING_FOR_SALT,
  WAITING_FOR_PASSWD,
  ENCRYPTING_FILE,
} StateName;

typedef struct {
  StateName state;
  char *file_path;
  char *prompt_text;
} AppState;

typedef struct {
  char passwd[MAX_PASSWD_CHARS + 1];
  char salt[MAX_SALT_CHARS + 1];
  int lettercount;
} PasswordDetails;

int main(void) {
  AppState state = {0};
  state.state = WAITING_FOR_FILE;
  state.prompt_text = "Drop a file here to encrypt it";
  state.file_path = "";

  PasswordDetails passwd_details = {0};
  passwd_details.lettercount = 0;
  passwd_details.passwd[0] = '\0';
  passwd_details.salt[0] = '\0';

  InitWindow(INITIAL_WIDTH, INITIAL_HEIGHT, "AES-256 file encryption");

  int monitor_number = GetCurrentMonitor();
  int window_width = GetMonitorWidth(monitor_number) / 2;
  int window_height = GetMonitorHeight(monitor_number) * 2 / 3;
  SetWindowSize(window_width, window_height);
  SetWindowState(FLAG_WINDOW_RESIZABLE);
  SetWindowMinSize(window_width/1.2, window_height/2.0);

  SetTargetFPS(60);

  Font font = LoadFontEx("fonts/Alegreya-VariableFont_wght.ttf", FONTSIZE, NULL, 0);
  // Initialize the libgcrypt library
  if (!gcry_check_version(GCRYPT_VERSION)) {
      handle_error("Libgcrypt version mismatch");
  }
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

  while (!WindowShouldClose()) {
    if (IsWindowResized()) {
      window_width = GetScreenWidth();
      window_height = GetScreenHeight();
    }

    if (IsFileDropped()) {
      FilePathList files = LoadDroppedFiles();
      assert(files.count > 0 && "Dropping files should never result in zero files on the drop list, right?");

      state.file_path = calloc(strlen(files.paths[0])+1, sizeof(char));
      strcpy(state.file_path, files.paths[0]);
      TraceLog(LOG_INFO, "Received a file to open");
      passwd_details.lettercount = 0;
      passwd_details.passwd[0] = '\0';
      state.state = WAITING_FOR_SALT;

      UnloadDroppedFiles(files);
    }

    BeginDrawing();
      ClearBackground(BACKGROUND_COLOUR);

      if (state.state == WAITING_FOR_FILE) {
        Vector2 prompt_size = MeasureTextEx(font, state.prompt_text, FONTSIZE, 0);
        Vector2 prompt_loc = {.x = window_width/2.0 - prompt_size.x/2.0, .y = window_height/2.0 - prompt_size.y/2.0};
        DrawTextEx(font, state.prompt_text, prompt_loc, FONTSIZE, 0, LIGHTGRAY);
      } else if (state.state == WAITING_FOR_SALT) {
        state.prompt_text = "Please add a string to salt the encryption\n\n(This should match the salt used in your decryption application)";
        Vector2 prompt_size = MeasureTextEx(font, state.prompt_text, FONTSIZE, 0);
        Vector2 prompt_loc = {.x = window_width/2.0 - prompt_size.x/2.0, .y = window_height/2.0 - 3.0*prompt_size.y/2.0};
        DrawTextEx(font, state.prompt_text, prompt_loc, FONTSIZE, 0, LIGHTGRAY);

        Rectangle textBox = {.x=prompt_loc.x, .y=prompt_loc.y+10+prompt_size.y, .width=prompt_size.x, .height=prompt_size.y/2.0};
        DrawRectangleRec(textBox, LIGHTGRAY);

        int key = GetCharPressed();
        // Check if more characters have been pressed on the same frame
        while (key > 0) {
            // NOTE: Only allow keys in range [32..125]
            if ((key >= 32) && (key <= 125) && (passwd_details.lettercount < MAX_SALT_CHARS)) {
                passwd_details.salt[passwd_details.lettercount] = (char)key;
                passwd_details.salt[passwd_details.lettercount+1] = '\0'; // Add null terminator at the end of the string.
                passwd_details.lettercount++;
            }
            key = GetCharPressed();  // Check next character in the queue
        }

        if (IsKeyPressed(KEY_BACKSPACE)) {
            passwd_details.lettercount--;
            if (passwd_details.lettercount < 0) passwd_details.lettercount = 0;
            passwd_details.salt[passwd_details.lettercount] = '\0';
        }

        if (IsKeyPressed(KEY_ENTER)) {
          passwd_details.lettercount = 0;
          passwd_details.passwd[0] = '\0';
          state.state = WAITING_FOR_PASSWD;
        }
        float spacing = 1;
        Vector2 passwd_text_size = MeasureTextEx(font, passwd_details.salt, FONTSIZE, spacing);
        DrawTextEx(font, passwd_details.salt, (Vector2){.x=window_width/2.0 - passwd_text_size.x/2.0, .y=textBox.y}, FONTSIZE, spacing, BACKGROUND_COLOUR);
      } else if (state.state == WAITING_FOR_PASSWD) {
        state.prompt_text = "Please provide a password for the file";
        Vector2 prompt_size = MeasureTextEx(font, state.prompt_text, FONTSIZE, 0);
        Vector2 prompt_loc = {.x = window_width/2.0 - prompt_size.x/2.0, .y = window_height/2.0 - 3.0*prompt_size.y/2.0};
        DrawTextEx(font, state.prompt_text, prompt_loc, FONTSIZE, 0, LIGHTGRAY);

        Rectangle textBox = {.x=prompt_loc.x, .y=prompt_loc.y+10+prompt_size.y, .width=prompt_size.x, .height=prompt_size.y};
        DrawRectangleRec(textBox, LIGHTGRAY);

        int key = GetCharPressed();
        // Check if more characters have been pressed on the same frame
        while (key > 0) {
            // NOTE: Only allow keys in range [32..125]
            if ((key >= 32) && (key <= 125) && (passwd_details.lettercount < MAX_PASSWD_CHARS)) {
                passwd_details.passwd[passwd_details.lettercount] = (char)key;
                passwd_details.passwd[passwd_details.lettercount+1] = '\0'; // Add null terminator at the end of the string.
                passwd_details.lettercount++;
            }
            key = GetCharPressed();  // Check next character in the queue
        }

        if (IsKeyPressed(KEY_BACKSPACE)) {
            passwd_details.lettercount--;
            if (passwd_details.lettercount < 0) passwd_details.lettercount = 0;
            passwd_details.passwd[passwd_details.lettercount] = '\0';
        }

        if (IsKeyPressed(KEY_ENTER)) {
          state.state = ENCRYPTING_FILE;
        }
        float spacing = 2;
        Vector2 passwd_text_size = MeasureTextEx(font, passwd_details.passwd, FONTSIZE, spacing);
        DrawTextEx(font, passwd_details.passwd, (Vector2){.x=window_width/2.0 - passwd_text_size.x/2.0, .y=textBox.y}, FONTSIZE, spacing, BACKGROUND_COLOUR);
      } else if (state.state == ENCRYPTING_FILE) {
        // Call the function to encrypt the file
        encrypt_file(state.file_path, passwd_details.salt, passwd_details.passwd);

        state.prompt_text = "File encrypted. Please drop another file for encryption";
        passwd_details.salt[0] = '\0';
        passwd_details.passwd[0] = '\0';
        state.state = WAITING_FOR_FILE;
      }
    EndDrawing();
  }

  // Clean up libgcrypt
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 1);

  return EXIT_SUCCESS;
}

