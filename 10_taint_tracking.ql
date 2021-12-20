import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap(){
        // exists(MacroInvocation mi | mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and 
        exists(MacroInvocation mi | mi.getMacro().getName().regexpMatch("ntoh(s|l|ll)") and 
        this = mi.getExpr())
    }
}

class Config extends TaintTracking::Configuration {
    Config() {
        this = "NetworkToMemFuncLength"
    }
    override predicate isSource(DataFlow::Node source) {
     source.asExpr() instanceof NetworkByteSwap
    }
    override predicate isSink(DataFlow::Node sink) {
        // 判断函数调用是否为 memcpy 且 sink 的代码片段是否为 memcpy 的第三个参数, 并且第二个参数不是常量
        exists(FunctionCall fc | 
            fc.getTarget().getName() = "memcpy" and 
            // fc.getTarget().hasName("memcpy") and
            sink.asExpr() = fc.getArgument(2) and
            not fc.getArgument(1).isConstant()
            )
    }

}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink, FunctionCall call
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"

// import cpp
// from FunctionCall call
// where call.getTarget().getName() = "memcpy"
// select call.getNumberOfArguments(), call.getArgument(1)
