global num_of_responses:int;
global num_of_404_responses:int;
global num_of_uniqueURL:int;

event zeek_init()
{
    local r1=SumStats::Reducer($stream="scan_detect_code.lookup", $apply=set(SumStats::UNIQUE));
    local r2=SumStats::Reducer($stream="scan_detect_404.lookup", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="scan_detect_url",
                      $epoh=10min,
                      $reducer=set(r1,r2,r3),
                      $epoch_result(ts:time, key:SumStats:Key, result:SumStats::Result)=
                      {
                          local s1=result["scan_detect_code.lookup"];
                          local s2=result["scan_detect_404.lookup"];
                          num_of_responses=s1$num;
                          num_of_404_responses=s2$num;
                          num_of_uniqueURL=s2$unique;
                          if ( (num_of_404_responses>2) && (num_of_404_responses>0.2*num_of_responses) && (num_of_uniqueURL>0.5*num_of_404_responses) )
                              print fmt("%s is a scanner with %d scan attemps on %d urls", c$id$orig_h, num_of_404_responses, num_of_uniqueURL);
                      }
                      
}


event http_reply(c:connection,version:string,code:count,reason:string)
{
    SumStats::observe("scan_detect_code.lookup", [$host=c$id$orig_h], [$str=code]);
    if (code==404)
        SumStats::observe("scan_detect_404.lookup", [$host=c$id$orig_h], [$str=c$http$uid]);
}


