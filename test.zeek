type UaMsg:record
{
    num:int;
    name:set[string];
};

global srcIP_ua:table[addr] of UaMsg;

event http_header(c:connection,is_orig:bool,name:string,value:string)
{
    if (name=="USER-AGENT"){
        if (c$id$orig_h in srcIP_ua){
            for (i,j in srcIP_ua){
                if (value !in j$name){
                    add j$name[value];
                    ++srcIP_ua[c$id$orig_h]$num;
                    if (srcIP_ua[c$id$orig_h]$num==4){
                        print fmt("%s is proxy",c$id$orig_h);
                        break;
                    }
                }
            }
            
        }
        else {
            local x:UaMsg;
            x$num=1;
            add x$name[value];
            srcIP_ua[c$id$orig_h]=x;
        }
        
    }
}
