import cpp

from FunctionCall fc, Function f
where 
    fc.getTarget().getName() = "memcpy"
select fc