
import cpp
class NetworkByteSwap extends Expr {
    NetworkByteSwap(){
        // exists(MacroInvocation mi | mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and 
        exists(MacroInvocation mi | mi.getMacro().getName().regexpMatch("ntoh(s|l|ll)") and 
        this = mi.getExpr())
    }
}

from NetworkByteSwap nbs
select nbs, "diy Class"