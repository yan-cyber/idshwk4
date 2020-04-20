global num_of_responses:table[addr] of count;
global num_of_404_responses:count;
global num_of_uniqueURL:count;
#global urls:table[connection] of string;

event zeek_init()
{
    local r1:SumStats::Reducer=[$stream="scan_detect_404.lookup", $apply=set(SumStats::UNIQUE)];
    SumStats::create([$name="scan_detect_url",
                      $epoch=10min,
                      $reducers=set(r1),
                      $epoch_result(ts:time, key:SumStats::Key, result:SumStats::Result)=
                      {
                          num_of_404_responses=result["scan_detect_404.lookup"]$num;
                          num_of_uniqueURL=result["scan_detect_404.lookup"]$unique;
                          if ( (num_of_404_responses>2) && (num_of_404_responses>0.2*num_of_responses[key$host]) && (num_of_uniqueURL>0.5*num_of_404_responses) )
                              print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, num_of_404_responses, num_of_uniqueURL);
                      }]);
                      
}

event http_reply(c:connection,version:string,code:count,reason:string)
{

    if (c$id$orig_h in num_of_responses)
        ++num_of_responses[c$id$orig_h];
        else 
            num_of_responses[c$id$orig_h]=1;
    if (code==404)
        SumStats::observe("scan_detect_404.lookup", [$host=c$id$orig_h], [$str=c$http$uri]);
}
