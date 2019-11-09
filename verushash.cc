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
CVerusHashV2* vh2b1;

bool initialized = false;

void initialize() {
    if (!initialized) {
        CVerusHash::init();
        CVerusHashV2::init();
    }
    
    vh = new CVerusHash();
    vh2 = new CVerusHashV2(SOLUTION_VERUSHHASH_V2);
    vh2b1 = new CVerusHashV2(SOLUTION_VERUSHHASH_V2_1);
    
    initialized = true;
}

void verusInit(const FunctionCallbackInfo<Value>& args) {
    initialize();
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

void verusHashV2b1(const FunctionCallbackInfo<Value>& args) {
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


    vh2b1->Reset();
    vh2b1->Write((const unsigned char *)buff, Buffer::Length(buffer));
    vh2b1->Finalize2b((unsigned char *)result);
    args.GetReturnValue().Set(Buffer::Copy(isolate, result, 32).ToLocalChecked());
}

void init(Local<Object> exports) {
  NODE_SET_METHOD(exports, "init", verusInit);

  NODE_SET_METHOD(exports, "hash", verusHash);          //VerusHash V1
  NODE_SET_METHOD(exports, "hash2", verusHashV2);       //VerusHash V2
  NODE_SET_METHOD(exports, "hash2b", verusHashV2b);     //VerusHash V2B
  NODE_SET_METHOD(exports, "hash2b1", verusHashV2b1);   //VerusHash V2B1
}

NODE_MODULE(verushash, init)
