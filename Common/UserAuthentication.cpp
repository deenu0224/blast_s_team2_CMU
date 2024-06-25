#include "UserAuthentication.h"
#include "Crypto.h"
#include "Message.h"
#include <openssl/rand.h>
#include <fstream> 
#include <sstream>
#include <ctime>
#include <vector>
#include <cstring>
#include <unordered_map>
#include <mutex>

// 전역 변수로 TokenInfo 선언
TokenInfo global_token_info;

#define USER_FILE       "userinfo.dat" 
#define AUTH_FAIL_FILE  "failinfo.dat"

// 전역 변수 선언
unsigned char KEY[32];
char HMAC_KEY[32];
std::once_flag load_keys_flag;

#if 1

bool load_keys() {
    const char* aes_key_file = "enc_key";
    const char* hmac_key_file = "hmac_key";

    std::ifstream aes_key_ifs(aes_key_file, std::ios::binary);
    if (!aes_key_ifs) {
        std::cerr << "Failed to open AES key file: " << aes_key_file << std::endl;
        return false;
    }

    std::ifstream hmac_key_ifs(hmac_key_file, std::ios::binary);
    if (!hmac_key_ifs) {
        std::cerr << "Failed to open HMAC key file: " << hmac_key_file << std::endl;
        return false;
    }

    aes_key_ifs.read((char*)KEY, 32);
    if (aes_key_ifs.gcount() != 32) {
        std::cerr << "Failed to read 32 bytes from AES key file" << std::endl;
        return false;
    }

    hmac_key_ifs.read(HMAC_KEY, 32);
    if (hmac_key_ifs.gcount() != 32) {
        std::cerr << "Failed to read 32 bytes from HMAC key file" << std::endl;
        return false;
    }

    return true;
}

void initialize_keys() {
    std::call_once(load_keys_flag, []() {
        if (!load_keys()) {
            std::cerr << "Failed to load keys" << std::endl;
            return;
        }
    });
}


bool save_user(const UserHandle& user_handle) {
    std::ifstream in_file(USER_FILE, std::ios::binary);
    bool user_found = false;
    std::streampos current_pos = in_file.tellg();
    if (!in_file.is_open()) return false;
    StoredUserInfo sUserInfo = {0,};
    printf("Store user info");

    std::vector<unsigned char> iv = generate_random_bytes(16);
    
    memcpy(sUserInfo.UserId, user_handle.User.UserId, sizeof(sUserInfo.UserId));
    memcpy(sUserInfo.Iv, iv.data(), sizeof(sUserInfo.Iv));

    std::vector<unsigned char> buffer(sizeof(UserInfo) + HMAC_SIZE);
    memcpy(buffer.data(), &user_handle.User, sizeof(UserInfo));
    memcpy(buffer.data() + sizeof(UserInfo), user_handle.Signature, HMAC_SIZE);

    // Encrypt the buffer
    std::vector<unsigned char> encrypted_buffer(buffer.size() + AES_BLOCK_SIZE);
    int encrypted_len = 0;
    if (!aes_encrypt(KEY, iv.data(), buffer.data(), buffer.size(), encrypted_buffer.data(), encrypted_len)) {
        printf("encryption failed");
        return false;
    }

    sUserInfo.EncryptedDataLen = encrypted_len;
    sUserInfo.EncryptedData = new char[encrypted_len];
    
    memset(sUserInfo.EncryptedData, 0x0, sUserInfo.EncryptedDataLen);
    memcpy(sUserInfo.EncryptedData, encrypted_buffer.data(), sUserInfo.EncryptedDataLen);
     
    while (in_file.peek() != EOF) {
        StoredUserInfo tmpUserInfo = {0,};
        current_pos = in_file.tellg();
        // UserId를 읽음
        in_file.read(reinterpret_cast<char*>(&tmpUserInfo.UserId), sizeof(tmpUserInfo.UserId));
        if (!in_file.good()) break;

        // UserId 비교
        if (memcmp(tmpUserInfo.UserId, sUserInfo.UserId, sizeof(tmpUserInfo.UserId)) == 0) {
            printf("User found\n");
            user_found = true;
            break;
        } else {
            // 일치하지 않으면 다음 데이터를 건너뜀
            in_file.ignore(sizeof(sUserInfo.Iv));
            unsigned int encrypted_data_len = 0;
            in_file.read(reinterpret_cast<char*>(&encrypted_data_len), sizeof(sUserInfo.EncryptedDataLen));
            in_file.ignore(encrypted_data_len);
        }
     }

    in_file.close();
    std::fstream out_file(USER_FILE, std::ios::binary | std::ios::in | std::ios::out);

    if (user_found) {
        out_file.seekp(current_pos);
    } else {
         out_file.seekp(0, std::ios::end);
    }

    out_file.write(reinterpret_cast<const char*>(&sUserInfo), sizeof(sUserInfo) - sizeof(sUserInfo.EncryptedData));
    out_file.write(sUserInfo.EncryptedData, sUserInfo.EncryptedDataLen);

    out_file.close();

    delete[] sUserInfo.EncryptedData;
    return out_file.good();
}

bool load_user(const std::string& user_id, UserHandle& user_handle) {
    std::ifstream file(USER_FILE, std::ios::binary);
    printf("load user info start");
    if (!file.is_open()) {
        std::cerr << "Not open user info" << std::endl;
        return false;
    }

     while (file.peek() != EOF) {
        StoredUserInfo sUserInfo = {0,};

        // UserId를 읽음
        file.read(reinterpret_cast<char*>(&sUserInfo.UserId), sizeof(sUserInfo.UserId));
        if (!file.good()) break;

        // UserId 비교
        if (memcmp(sUserInfo.UserId, user_id.c_str(), sizeof(sUserInfo.UserId)) == 0) {
            // Iv, EncryptedDataLen을 읽음
            file.read(reinterpret_cast<char*>(&sUserInfo.Iv), sizeof(sUserInfo.Iv));
            file.read(reinterpret_cast<char*>(&sUserInfo.EncryptedDataLen), sizeof(sUserInfo.EncryptedDataLen));

            // EncryptedData를 읽음
            sUserInfo.EncryptedData = new char[sUserInfo.EncryptedDataLen];
            memset(sUserInfo.EncryptedData, 0x0, sUserInfo.EncryptedDataLen);
            file.read(sUserInfo.EncryptedData, sUserInfo.EncryptedDataLen);

            if (!file.good()) {
                std::cerr << "Fail to read a file" << std::endl;
                delete[] sUserInfo.EncryptedData;
                return false;
            }

            // EncryptedData를 복호화
            std::vector<unsigned char> decrypted_buffer(sizeof(UserInfo) + sizeof(user_handle.Signature));
            int decrypted_len = 0;

            if (!aes_decrypt(KEY, sUserInfo.Iv, reinterpret_cast<unsigned char*>(sUserInfo.EncryptedData), sUserInfo.EncryptedDataLen, decrypted_buffer.data(), decrypted_len)) {
                std::cerr << "Fail to decrypt." << std::endl;
                delete[] sUserInfo.EncryptedData;
                return false;
            }

            decrypted_buffer.resize(decrypted_len);

            // UserInfo와 Signature를 복원
            memcpy(&user_handle.User, decrypted_buffer.data() , sizeof(UserInfo));
            memcpy(user_handle.Signature, decrypted_buffer.data() + sizeof(UserInfo), HMAC_SIZE);

            // 할당된 메모리 해제
            delete[] sUserInfo.EncryptedData;

            return true; // 일치하는 UserId를 찾았으므로 true 반환
        } else {
            // 일치하지 않으면 다음 데이터를 건너뜀
            file.ignore(sizeof(sUserInfo.Iv));
            unsigned int encrypted_data_len = 0;
            file.read(reinterpret_cast<char*>(&encrypted_data_len), sizeof(sUserInfo.EncryptedDataLen));
            file.ignore(encrypted_data_len);
        }
     }
    // user 찾지 못함.
    return false;
}

int check_userid(const std::string& user_id) {
    std::ifstream file(USER_FILE, std::ios::binary);
    // 1. user_file이 없으면 파일을 새로운 파일을 생성하고 1을 반환
    if (!file.is_open()) {
        std::ofstream new_file(USER_FILE, std::ios::binary);
        if (!new_file.is_open()) {
            std::cerr << "Failed to create user file" << std::endl;
            return -1; // 파일 생성 실패
        }
        return 1; // 파일이 없으면 새로 생성
    }

     while (file.peek() != EOF) {
        StoredUserInfo sUserInfo = {0,};
        // UserId를 읽음
        file.read(reinterpret_cast<char*>(&sUserInfo.UserId), sizeof(sUserInfo.UserId));
        if (!file.good()) break;
        //printf("sUserInfo.UserId= %s", sUserInfo.UserId);
        // UserId 비교
        if (memcmp(sUserInfo.UserId, user_id.c_str(), sizeof(sUserInfo.UserId)) == 0) {
             std::cerr << "Already enrolled user" << std::endl;
            return -2; // 이미 등록된 유저가 있음.
        } else {
            // 일치하지 않으면 다음 데이터를 건너뜀
            file.ignore(sizeof(sUserInfo.Iv));
            unsigned int encrypted_data_len = 0;
            file.read(reinterpret_cast<char*>(&encrypted_data_len), sizeof(encrypted_data_len));
            //printf("encrypted_data_len = %d", encrypted_data_len);
            file.ignore(encrypted_data_len);
        }
     }
     // 일치 하는 userid 없음. 등록 가능.
    return 0;
}


// FailInfo 파일을 로드하는 함수
bool load_fail_info(const std::string& user_id_str, FailHandle& fail_handle) {
    std::ifstream file(AUTH_FAIL_FILE, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Do not exist fail info" << std::endl;
        return false;
    }

     while (file.peek() != EOF) {
        StoredFailInfo sFailInfo = {0,};

        // UserId를 읽음
        file.read(reinterpret_cast<char*>(&sFailInfo.UserId), sizeof(sFailInfo.UserId));
        if (!file.good()) break;

        // UserId 비교
        if (memcmp(sFailInfo.UserId, user_id_str.c_str(), sizeof(sFailInfo.UserId)) == 0) {
            printf("Found user in load_fail_info");
            // Iv, EncryptedDataLen을 읽음
            file.read(reinterpret_cast<char*>(&sFailInfo.Iv), sizeof(sFailInfo.Iv));
            file.read(reinterpret_cast<char*>(&sFailInfo.EncryptedDataLen), sizeof(sFailInfo.EncryptedDataLen));

            // EncryptedData를 읽음
            sFailInfo.EncryptedData = new char[sFailInfo.EncryptedDataLen];
            memset(sFailInfo.EncryptedData, 0x0, sFailInfo.EncryptedDataLen);
            file.read(sFailInfo.EncryptedData, sFailInfo.EncryptedDataLen);

            if (!file.good()) {
                std::cerr << "파일에서 데이터를 읽는 도중 오류가 발생했습니다." << std::endl;
                delete[] sFailInfo.EncryptedData;
                return false;
            }

            // EncryptedData를 복호화
            std::vector<unsigned char> decrypted_buffer(sizeof(FailHandle));
            int decrypted_len = 0;

            if (!aes_decrypt(KEY, sFailInfo.Iv, reinterpret_cast<unsigned char*>(sFailInfo.EncryptedData), sFailInfo.EncryptedDataLen, decrypted_buffer.data(), decrypted_len)) {
                std::cerr << "decryption failed" << std::endl;
                delete[] sFailInfo.EncryptedData;
                return false;
            }

            decrypted_buffer.resize(decrypted_len);

            // UserInfo와 Signature를 복원
            memcpy(&fail_handle, decrypted_buffer.data() , sizeof(FailHandle));

            // 할당된 메모리 해제
            delete[] sFailInfo.EncryptedData;

            return true; // 일치하는 UserId를 찾았으므로 true 반환
        } else {
            // 일치하지 않으면 다음 데이터를 건너뜀
            file.ignore(sizeof(sFailInfo.Iv));
            unsigned int encrypted_data_len = 0;
            file.read(reinterpret_cast<char*>(&encrypted_data_len), sizeof(sFailInfo.EncryptedDataLen));
            file.ignore(encrypted_data_len);
        }
     }
    // user 찾지 못함.
    return false;  
}

// FailInfo 파일을 저장하는 함수
bool save_fail_info(FailHandle& fail_handle) {
    std::ifstream in_file(AUTH_FAIL_FILE, std::ios::binary);
    bool user_found = false;

    if (!in_file.is_open()) {
        std::ofstream new_file(AUTH_FAIL_FILE, std::ios::binary);
        if (!new_file.is_open()) {
            std::cerr << "Failed to create fail file" << std::endl;
            return -1; // 파일 생성 실패
        }

        new_file.close();
        in_file.open(AUTH_FAIL_FILE, std::ios::binary);
        user_found = true;
    }

    std::streampos current_pos = in_file.tellg();
    StoredFailInfo sFailInfo = {0,};

    std::vector<unsigned char> iv = generate_random_bytes(16);
    
    memcpy(sFailInfo.UserId, fail_handle.UserFailInfo.UserId, sizeof(sFailInfo.UserId));
    memcpy(sFailInfo.Iv, iv.data(), sizeof(sFailInfo.Iv));

    std::vector<unsigned char> buffer(sizeof(FailInfo) + HMAC_SIZE);
    memcpy(buffer.data(), &fail_handle.UserFailInfo, sizeof(FailInfo));
    memcpy(buffer.data() + sizeof(FailInfo), fail_handle.Signature, HMAC_SIZE);

    // Encrypt the buffer
    std::vector<unsigned char> encrypted_buffer(buffer.size() + AES_BLOCK_SIZE);
    int encrypted_len = 0;
    if (!aes_encrypt(KEY, iv.data(), buffer.data(), buffer.size(), encrypted_buffer.data(), encrypted_len)) {
        std::cerr << "encrypt fail " << std::endl;
        return false;
    }

    sFailInfo.EncryptedDataLen = encrypted_len;
    sFailInfo.EncryptedData = new char[sFailInfo.EncryptedDataLen];
    
    memset(sFailInfo.EncryptedData, 0x0, sFailInfo.EncryptedDataLen);
    memcpy(sFailInfo.EncryptedData, encrypted_buffer.data(), sFailInfo.EncryptedDataLen);

    while (in_file.peek() != EOF) {
        StoredFailInfo tmpStoredFailInfo = {0,};
        // 현재 파일 오프셋을 저장.
        current_pos = in_file.tellg();
        // UserId를 읽음
        in_file.read(reinterpret_cast<char*>(&tmpStoredFailInfo.UserId), sizeof(tmpStoredFailInfo.UserId));
        if (!in_file.good()) break;

        // UserId 비교
        if (memcmp(tmpStoredFailInfo.UserId, sFailInfo.UserId, sizeof(tmpStoredFailInfo.UserId)) == 0) {
            std::cerr << "user found, replace saved data" << std::endl;
            // 파일 오프셋을 저장할 위치로 복원
            //in_file.seekg(current_pos);
            user_found = true;
            break;
        } else {
            // 일치하지 않으면 다음 데이터를 건너뜀
            in_file.ignore(sizeof(tmpStoredFailInfo.Iv));
            unsigned int encrypted_data_len;
            in_file.read(reinterpret_cast<char*>(&encrypted_data_len), sizeof(encrypted_data_len));
            in_file.ignore(encrypted_data_len);
        }
    }
    in_file.close();
    std::fstream out_file(AUTH_FAIL_FILE, std::ios::binary | std::ios::in | std::ios::out);

    if (user_found) {
        out_file.seekp(current_pos);
    } else {
         out_file.seekp(0, std::ios::end);
    }

    out_file.write(reinterpret_cast<const char*>(&sFailInfo), sizeof(sFailInfo) - sizeof(sFailInfo.EncryptedData));
    out_file.write(sFailInfo.EncryptedData, sFailInfo.EncryptedDataLen);

    out_file.close();

    delete[] sFailInfo.EncryptedData;
    return out_file.good();
}

// AUTH_FAIL_FILE 파일에서 해당 유저의 실패 정보를 삭제하는 함수
bool delete_fail_info(const std::string& user_id_str) {
    std::ifstream file(AUTH_FAIL_FILE, std::ios::binary);
    std::streampos delete_pos = file.tellg();
    StoredFailInfo deleteFailInfo = {0,};
    bool user_found = false;

    if (!file.is_open()) {
        std::cerr << "There is no fail info" << std::endl;
        return true;
    }
    
    while (file.peek() != EOF) {
        delete_pos = file.tellg();
        // UserId를 읽음
        file.read(reinterpret_cast<char*>(&deleteFailInfo.UserId), sizeof(deleteFailInfo.UserId));
        if (!file.good()) break;

        // UserId 비교
        if (memcmp(deleteFailInfo.UserId, user_id_str.c_str(), sizeof(deleteFailInfo.UserId)) == 0) {
            // Iv, EncryptedDataLen을 읽음
            std::cerr << "Found for deleting user" << std::endl;
            file.ignore(sizeof(deleteFailInfo.Iv));
            file.read(reinterpret_cast<char*>(&deleteFailInfo.EncryptedDataLen), sizeof(deleteFailInfo.EncryptedDataLen));
            user_found = true;
            break;
        } else {
            // 일치하지 않으면 다음 데이터를 건너뜀
            file.ignore(sizeof(deleteFailInfo.Iv));
            unsigned int encrypted_data_len = 0;
            file.read(reinterpret_cast<char*>(&encrypted_data_len), sizeof(deleteFailInfo.EncryptedDataLen));
            file.ignore(encrypted_data_len);
        }
     }

    file.close();

    if(!user_found)
    {   // user not found
        return true;
    }

    std::fstream out_file(AUTH_FAIL_FILE, std::ios::binary | std::ios::in | std::ios::out);
    if (!out_file.is_open()) {
        std::cerr << "Failed to open fail info file for writing" << std::endl;
        return false;
    }

    deleteFailInfo.EncryptedData = new char[deleteFailInfo.EncryptedDataLen];
    memset(deleteFailInfo.EncryptedData, 0x0, deleteFailInfo.EncryptedDataLen);
    int encrypted_len = deleteFailInfo.EncryptedDataLen;
    deleteFailInfo.EncryptedDataLen = 0;   //initialize

    out_file.seekp(delete_pos);
    out_file.write(reinterpret_cast<const char*>(&deleteFailInfo), sizeof(deleteFailInfo) - sizeof(deleteFailInfo.EncryptedData));
    out_file.write(deleteFailInfo.EncryptedData, encrypted_len);
    out_file.close();
    
    delete[] deleteFailInfo.EncryptedData;

    return out_file.good();
}

int ResetToken(const std::vector<unsigned char>& token) {
    if (TokenVerifier(token)) {
        printf("ResetToken Invaild token\n");
        return INVALID_TOKEN;
    }
    memset(&global_token_info, 0,  sizeof(TokenInfo));
    return SUCCESS;
}

int GlobalResetToken() {
    memset(&global_token_info, 0,  sizeof(TokenInfo));
    return SUCCESS;
}


int TokenVerifier(const std::vector<unsigned char>& token) {
// 1. token이 유효한지 검증
    TokenInfo nullToken = {0,};
    if (0 == memcmp(&nullToken, &global_token_info, sizeof(TokenInfo))) {
        std::cerr << "There is not an issued token" << std::endl;
        return INVALID_TOKEN;
    }
    std::vector<unsigned char> token_hmac_input(sizeof(TokenInfo));
    memcpy(token_hmac_input.data(), &global_token_info, sizeof(TokenInfo));

    std::vector<unsigned char> expected_token = calculate_hmac(HMAC_KEY, token_hmac_input.data(), token_hmac_input.size());

    if (token != expected_token) {
        std::cerr << "Invalid token" << std::endl;
        return INVALID_TOKEN;
    }
    return 0;
}

int EnrollPwd(const char* username, const char* password) {
    std::vector<unsigned char> user_id = sha256(username);
    std::string user_id_str(user_id.begin(), user_id.end());
    int ret = -1;

    UserHandle user_handle = {0,};

    ret = check_userid(user_id_str);
    if (ret == -1) {
        std::cerr << "Failed to create or open user file" << std::endl;
        return INVALID_OPERATION;
    }
    else if (ret == -2) {
        std::cerr << "User already exists" << std::endl;
        return EXIST_USER;
    }
    else if (ret == 1) {
        user_handle.User.Privilege = 1;   // 최초 등록은 admin으로 간주한다.
    }
        
    // Fill UserHandle
    memcpy(user_handle.User.UserId, user_id_str.c_str(), sizeof(user_handle.User.UserId));
    memcpy(user_handle.User.Name, username, sizeof(user_handle.User.Name));
    user_handle.User.Timestamp = std::time(nullptr);
    memcpy(user_handle.Password, password, sizeof(user_handle.Password));

    // Calculate HMAC
    std::vector<unsigned char> hmac = calculate_hmac(HMAC_KEY, &user_handle, sizeof(UserHandle) - sizeof(user_handle.Signature));
    std::copy(hmac.begin(), hmac.end(), user_handle.Signature);

    // Save UserHandle
    if (!save_user(user_handle)) {
        std::cerr << "Failed to save user" << std::endl;
        return INVALID_OPERATION;
    }

    return 0;
}

int VerifyPwd(const char* username, const char* password, std::vector<unsigned char>& token, FailInfo& fail_info) {
    // 1. 전달받은 username이 존재하는지 username의 hash를 계산 후 파일을 오픈하여 확인.
    std::vector<unsigned char> user_id = sha256(username);
    std::string user_id_str(user_id.begin(), user_id.end());
    UserHandle user_handle = {0,};
    FailHandle user_fail_handle = {0,};
    int ret = -1;
    std::time_t current_time = std::time(nullptr);
    std::ifstream file(USER_FILE, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open user file" << std::endl;
        return NOT_EXIST_USER;   //등록된 유저가 없음.
    }

    bool user_found = false;

    std::string line;
    const std::streamsize userid_size = 32;

    user_found = load_user(user_id_str, user_handle);

    file.close();

    if (!user_found) {
        std::cerr << "Does not found a user" << std::endl;
        return NOT_EXIST_USER;      // 유저 Not found
    } else {
        std::cerr << "Found a user" << std::endl;
    }

    // 1.2 파일로 저장된 FailInfo를 읽어와 복호화 한다.
    if (!load_fail_info(user_id_str, user_fail_handle)) {
        std::cerr << "Do not exist user_fail_handle" << std::endl;
        // 파일이 없으면 fail_info를 초기화한다.
        memset(&fail_info, 0, sizeof(FailInfo));
        memcpy(fail_info.UserId, user_id_str.c_str(), sizeof(fail_info.UserId));
        memcpy(fail_info.Privilege, user_handle.User.Privilege, sizeof(fail_info.Privilege));
    } else {
        // 1.3. 복호화된 FailInfo의 Signature를 HMAC으로 검증한다.
        std::cerr << "Found user_fail_handle" << std::endl;
        std::vector<unsigned char> fail_hmac_input(sizeof(FailInfo));
        memcpy(fail_hmac_input.data(), &user_fail_handle, sizeof(FailInfo));
        std::vector<unsigned char> calculated_fail_hmac = calculate_hmac(HMAC_KEY, fail_hmac_input.data(), fail_hmac_input.size());
        if (!std::equal(calculated_fail_hmac.begin(), calculated_fail_hmac.end(), user_fail_handle.Signature)) {
            std::cerr << "Fail info HMAC verification failed" << std::endl;
            return INVALID_OPERATION;
        }
        memcpy(&fail_info, &user_fail_handle.UserFailInfo, sizeof(FailInfo));

        // 1.4. 만약 Throttling이 존재하고, FailCount가 3이라면, 현재 시간이 Throttling 보다 작다면 return 한다.
        if (fail_info.FailCount >= 3) {
            if (current_time < fail_info.Throttle) {
                std::cerr << "Account is throttled" << std::endl;
                return AUTH_THROTTLED;
            } else { // Throttling이 종료되었으므로, count, throttle 초기화
                fail_info.FailCount = 0;
                fail_info.Throttle = 0;
            }
        }
    }
    // 2. 전달받은 password를 UserHandle의 Password에 할당
    memcpy(user_handle.Password, password, sizeof(user_handle.Password));

    // 3. 전달받은 password를 사용하여 HMAC을 계산
    std::vector<unsigned char> hmac_input(sizeof(UserHandle) - sizeof(user_handle.Signature));
    memcpy(hmac_input.data(), &user_handle.User, sizeof(UserInfo));
    memcpy(hmac_input.data() + sizeof(UserInfo), user_handle.Password, 32);
    std::vector<unsigned char> hmac = calculate_hmac(HMAC_KEY, hmac_input.data(), hmac_input.size());

    // 4. 계산한 HMAC과 UserHandle의 Signature를 비교
    if (!std::equal(hmac.begin(), hmac.end(), user_handle.Signature)) {
        FailHandle user_fail_handler = {0,};
        std::cerr << "Password verification failed" << std::endl;
        // 4.1. FailCount를 증가 시킨다. 만약 FailCount가 3이라면 Throttling에 1시간을 걸어 준다.
        fail_info.FailCount++;
        std::cerr << " fail_info.FailCount :: " << fail_info.FailCount << std::endl;
        if (fail_info.FailCount >= 3) {
            fail_info.Throttle = current_time + 3600; // 3600 Throttling, 30 s == 30
        }

        memcpy(&user_fail_handler, &fail_info, sizeof(FailInfo));
        // 4.2. FailInfo 변수를 HMAC하여 Signature에 저장한다.
        std::vector<unsigned char> fail_hmac_input(sizeof(FailInfo));
        memcpy(fail_hmac_input.data(), &user_fail_handler.UserFailInfo, sizeof(FailInfo));
        std::vector<unsigned char> new_fail_hmac = calculate_hmac(HMAC_KEY, fail_hmac_input.data(), fail_hmac_input.size());
        memcpy(user_fail_handler.Signature, new_fail_hmac.data(), new_fail_hmac.size());

        // 4.3. FailInfo를 파일에 저장한다.
        if (!save_fail_info(user_fail_handler)) {
            std::cerr << "Failed to save fail info" << std::endl;
            return INVALID_OPERATION;
        }
        return INVALID_PASSWORD;
    } else {
        // 4.4. 인증 성공 시 해당 유저의 FailInfo를 삭제한다.
        std::cerr << "Password verification Success" << std::endl;

        if (!delete_fail_info(user_id_str)) {
            std::cerr << "Failed to delete fail info for user" << std::endl;
            return INVALID_OPERATION;
        }
    }
    
    // 5. 전역 변수로 Token 발행
    if (RAND_bytes(reinterpret_cast<unsigned char*>(global_token_info.Challenge), sizeof(global_token_info.Challenge)) != 1) {
        std::cerr << "Failed to generate random bytes for challenge" << std::endl;
        return INVALID_OPERATION;
    }

    global_token_info.AuthType = 1;
    global_token_info.Timestamp = current_time;
    memcpy(global_token_info.UserId, user_id_str.c_str(), 32);
    global_token_info.Privilege = user_handle.User.Privilege;

    std::cerr << "user Privilege :: " << user_handle.User.Privilege << std::endl;
    //  비밀번호가 등록된지 30일이 초과했는지 확인
    
    if (current_time - user_handle.User.Timestamp > 30 * 24 * 60 * 60) {
        std::cerr << "Password expired" << std::endl;
        global_token_info.AuthType = 2;
        ret = EXPIRE_PASSWORD;  // return 패스워드 만료.
        return ret;
    }
    // 6. TokenInfo의 HMAC 값 계산 = token
    std::vector<unsigned char> token_hmac_input(sizeof(TokenInfo));
    memcpy(token_hmac_input.data(), &global_token_info, sizeof(TokenInfo));
    token = calculate_hmac(HMAC_KEY, token_hmac_input.data(), token_hmac_input.size());
    ret = 0;  // Success

    return ret;
}

int ChangePwd(const char* username, const char* password, const std::vector<unsigned char>& token) {
    // 1. 전달받은 username이 존재하는지 username의 hash를 계산 후 파일을 오픈하여 확인.
    std::vector<unsigned char> user_id = sha256(username);
    std::string user_id_str(user_id.begin(), user_id.end());
    UserHandle user_handle;
    printf("ChangePwd Enter");
    std::fstream file(USER_FILE, std::ios::binary | std::ios::in | std::ios::out);
    if (!file.is_open()) {
        std::cerr << "Failed to open user file" << std::endl;
        return INVALID_OPERATION;
    }

    bool user_found = false;

    user_found = load_user(user_id_str, user_handle);

    if (!user_found) {
        std::cerr << "User not found" << std::endl;
        return NOT_EXIST_USER;
    }

    // 2. token이 유효한지 검증
    std::vector<unsigned char> token_hmac_input(sizeof(TokenInfo));
    memcpy(token_hmac_input.data(), &global_token_info, sizeof(TokenInfo));
    std::vector<unsigned char> expected_token = calculate_hmac(HMAC_KEY, token_hmac_input.data(), token_hmac_input.size());

    if (token != expected_token) {
        std::cerr << "Invalid token" << std::endl;
        return INVALID_TOKEN;
    }
    // 토큰 type과 권한 체크.
    if(global_token_info.AuthType != 1 && global_token_info.AuthType != 2) {
    //ChangePw의 AuthType과 같아야만 한다.
        std::cerr << "Auth Type Error :" <<  global_token_info.AuthType  << std::endl;
        return INVALID_TOKEN;
    }

    if(global_token_info.Privilege != 1) {
        // 유저 체크, 유저가 token의 유저만 변경 가능.
        if (0 != memcmp(user_handle.User.UserId, global_token_info.UserId, sizeof(user_handle.User.UserId))) {
            std::cerr << "No permission defference user id" << std::endl;
            return NO_PERMISSION;
        }
    }

// 2. 전달받은 password를 UserHandle의 Password에 할당
    memcpy(user_handle.Password, password, sizeof(user_handle.Password));
    // 3. 전달받은 password를 사용하여 HMAC을 계산
     // Update enrolled timestamp
    user_handle.User.Timestamp = std::time(nullptr);

    std::vector<unsigned char> hmac_input(sizeof(UserHandle) - sizeof(user_handle.Signature));
    memcpy(hmac_input.data(), &user_handle.User, sizeof(UserInfo));
    memcpy(hmac_input.data() + sizeof(UserInfo), user_handle.Password, 32);
    std::vector<unsigned char> hmac = calculate_hmac(HMAC_KEY, hmac_input.data(), hmac_input.size());
    std::copy(hmac.begin(), hmac.end(), user_handle.Signature);

    // Save UserHandle
    if (!save_user(user_handle)) {
        std::cerr << "Failed to save user" << std::endl;
        return INVALID_OPERATION;
    }

    if(!global_token_info.Privilege) {
         std::cerr << "AuthType is changepw, token will destory" << std::endl;
        // 유저는 본인의 비밀번호 변경 완료 후 토큰 소멸, 유저 인증 재 필요.
        // 관리자는 유저의 비밀번호 변경, 관리자의 토큰은 유지.
        memset(&global_token_info, 0x0, sizeof(TokenInfo));
    }
    printf("chagnepwd END\n");
    file.close();
    return SUCCESS;
}
#endif

#if 0
// MOCKING API

int EnrollPwd(const char* username, const char* password)
{
    printf("EnrollPwd\n");
    return 0;
}
int VerifyPwd(const char* username, const char* password, std::vector<unsigned char>& token, FailInfo& fail_info)
{
     printf("VerifyPwd\n");
    return 0;
}
int ChangePwd(const char* username, const char* password, const std::vector<unsigned char>& token)
{
     printf("ChangePwd\n");
    return 0;
}
#endif