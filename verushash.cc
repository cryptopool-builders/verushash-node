#include <node.h>
#include <node_buffer.h>
#include <v8.h>

#include <stdint.h>
#include <vector>

#include "crypto/verus_hash.h"

using namespace node;
using namespace v8;

CVerusHash* vh;
CVerusHashV2* vh2;
bool initialized = false;

void initialize() {
    if (!initialized) {
        CVerusHash::init();
        CVerusHashV2::init();
    }
    vh = new CVerusHash();
    vh2 = new CVerusHashV2();
    initialized = true;
}

void verusInit(const FunctionCallbackInfo<Value>& args) {
    initialize();
    args.GetReturnValue().Set(args.This());
}

void verusUpdate(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (initialized == false){
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "call init() first!")));
            return;
        } while (0);
    }
    if (args.Length() < 1) {
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Wrong number of arguments")));
            return;
        } while (0);
    }

    Local<Object> buffer = args[0]->ToObject(isolate);
    if(!Buffer::HasInstance(buffer)) {
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Invalid buffer objects.")));
            return;
        } while (0);
    }
    
    const char *buff = Buffer::Data(buffer);
    vh->Write((const unsigned char *)buff, Buffer::Length(buffer));
    
    args.GetReturnValue().Set(args.This());
}

void verusDigest(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (initialized == false){
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "call init() first!")));
            return;
        } while (0);
    }
    char *result = new char[32];
    vh->Finalize((unsigned char *)result);
    args.GetReturnValue().Set(Buffer::Copy(isolate, result, 32).ToLocalChecked());
}

void verusReset(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (initialized == false){
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "call init() first!")));
            return;
        } while (0);
    }
    vh->Reset();
    args.GetReturnValue().Set(args.This());
}

void verusHash(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1) {
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Wrong number of arguments")));
            return;
        } while (0);
    }
    Local<Object> buffer = args[0]->ToObject(isolate);
    if(!Buffer::HasInstance(buffer)) {
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Invalid buffer objects.")));
            return;
        } while (0);
    }

    const char *buff = Buffer::Data(buffer);

    char *result = new char[32];
    
    if (initialized == false) {
        initialize();
    }
    verus_hash(result, buff, Buffer::Length(buffer));
    
    args.GetReturnValue().Set(Buffer::Copy(isolate, result, 32).ToLocalChecked());
}

void verusUpdateV2(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (initialized == false){
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "call init() first!")));
            return;
        } while (0);
    }
    if (args.Length() < 1) {
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Wrong number of arguments")));
            return;
        } while (0);
    }
    Local<Object> buffer = args[0]->ToObject(isolate);
    if(!Buffer::HasInstance(buffer)) {
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Invalid buffer objects.")));
            return;
        } while (0);
    }

    const char *buff = Buffer::Data(buffer);
    vh2->Write((const unsigned char *)buff, Buffer::Length(buffer));
    
    args.GetReturnValue().Set(args.This());
}

void verusDigestV2(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (initialized == false){
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "call init() first!")));
            return;
        } while (0);
    }
    char *result = new char[32];
    vh2->Finalize((unsigned char *)result);
    args.GetReturnValue().Set(Buffer::Copy(isolate, result, 32).ToLocalChecked());
}

void verusDigestV2b(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (initialized == false){
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "call init() first!")));
            return;
        } while (0);
    }
    char *result = new char[32];
    vh2->Finalize2b((unsigned char *)result);
    args.GetReturnValue().Set(Buffer::Copy(isolate, result, 32).ToLocalChecked());
}

void verusResetV2(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (initialized == false){
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "call init() first!")));
            return;
        } while (0);
    }
    vh2->Reset();
    args.GetReturnValue().Set(args.This());
}

void verusHashV2(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1) {
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Wrong number of arguments")));
            return;
        } while (0);
    }
    Local<Object> buffer = args[0]->ToObject(isolate);
    if(!Buffer::HasInstance(buffer)) {
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Invalid buffer objects.")));
            return;
        } while (0);
    }

    const char *buff = Buffer::Data(buffer);

    char *result = new char[32];
    
    if (initialized == false) {
        initialize();
    }

    vh2->Reset();
    vh2->Write((const unsigned char *)buff, Buffer::Length(buffer));
    vh2->Finalize((unsigned char *)result);
    args.GetReturnValue().Set(Buffer::Copy(isolate, result, 32).ToLocalChecked());
}

void verusHashV2b(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1) {
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Wrong number of arguments")));
            return;
        } while (0);
    }
    Local<Object> buffer = args[0]->ToObject(isolate);
    if(!Buffer::HasInstance(buffer)) {
        do {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Invalid buffer objects.")));
            return;
        } while (0);
    }

    const char *buff = Buffer::Data(buffer);

    char *result = new char[32];
    
    if (initialized == false) {
        initialize();
    }

    vh2->Reset();
    vh2->Write((const unsigned char *)buff, Buffer::Length(buffer));
    vh2->Finalize2b((unsigned char *)result);
    args.GetReturnValue().Set(Buffer::Copy(isolate, result, 32).ToLocalChecked());
}

void init(Local<Object> exports) {
  NODE_SET_METHOD(exports, "init", verusInit);
  NODE_SET_METHOD(exports, "update", verusUpdate);
  NODE_SET_METHOD(exports, "digest", verusDigest);
  NODE_SET_METHOD(exports, "reset", verusReset);
  NODE_SET_METHOD(exports, "hash", verusHash);
  NODE_SET_METHOD(exports, "update2", verusUpdateV2);
  NODE_SET_METHOD(exports, "digest2", verusDigestV2);
  NODE_SET_METHOD(exports, "digest2b", verusDigestV2b);
  NODE_SET_METHOD(exports, "reset2", verusResetV2);
  NODE_SET_METHOD(exports, "hash2", verusHashV2);
  NODE_SET_METHOD(exports, "hash2b", verusHashV2b);
}

NODE_MODULE(verushash, init)
