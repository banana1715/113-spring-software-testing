#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"

using namespace llvm;

struct LLVMPass : PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    LLVMContext &Ctx = M.getContext();

    // 1) Declare debug prototype: void debug(i32)
    FunctionCallee debugFunc = M.getOrInsertFunction(
      "debug",
      FunctionType::get(Type::getVoidTy(Ctx), {Type::getInt32Ty(Ctx)}, false)
    );
    ConstantInt *const48763 = ConstantInt::get(Type::getInt32Ty(Ctx), 48763);

    // 2) Locate main
    if (Function *F = M.getFunction("main")) {
      BasicBlock &entryBB = F->getEntryBlock();
      // Insert right after any allocas/PHIs in entry
      IRBuilder<> builder(&*entryBB.getFirstInsertionPt());

      // --- (40%) Call debug(48763) ---
      builder.CreateCall(debugFunc, {const48763});

      // --- (30%) Overwrite argc → 48763 ---
      // main signature is: i32 @main(i32 %argc, i8** %argv)
      Argument *argcArg = &*F->arg_begin();
      argcArg->replaceAllUsesWith(const48763);

      // --- (30%) Overwrite argv[1] → "hayaku... motohayaku!" ---
      Argument *argvArg = &*(std::next(F->arg_begin()));
      // Create a global constant string
      Value *strPtr = builder.CreateGlobalStringPtr("hayaku... motohayaku!");
      // Compute pointer to argv[1]: getelementptr i8*, i8** %argv, i64 1
      Value *idx1 = ConstantInt::get(Type::getInt64Ty(Ctx), 1);
      Value *ptrToArg1 = builder.CreateInBoundsGEP(
        argvArg->getType()->getPointerElementType(), // element type = i8*
        argvArg,                                     // base pointer i8**
        idx1
      );
      // Store the new string into argv[1]
      builder.CreateStore(strPtr, ptrToArg1);
    }

    return PreservedAnalyses::none();
  }
};

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0",
    [](PassBuilder &PB) {
      PB.registerOptimizerLastEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel) {
          MPM.addPass(LLVMPass());
        });
    }};
}
