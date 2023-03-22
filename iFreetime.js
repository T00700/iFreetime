#!name=爱阅三秒跳广告
#!desc="卡广告领奖励,请开启MITM或者HTTPS解密(更新日期:2023.03.01)"
[Rule]
# DOMAIN,v.gdt.qq.com,REJECT
DOMAIN,video-dsp.pddpic.com,REJECT
DOMAIN,adim.pinduoduo.com,REJECT
DOMAIN,images.pinduoduo.com,REJECT
DOMAIN-SUFFIX,bytedance.com,REJECT
DOMAIN-SUFFIX,pglstatp-toutiao.com,REJECT
DOMAIN-SUFFIX,app-measurement.com,REJECT
DOMAIN-SUFFIX,shenbabao.com,REJECT
DOMAIN-SUFFIX,umeng.com,REJECT
DOMAIN-SUFFIX,umengcloud.com,REJECT
DOMAIN-SUFFIX,bytescm.com,REJECT
DOMAIN-SUFFIX,ctobsnssdk.com,REJECT
DOMAIN-SUFFIX,snssdk.com,REJECT
[URL Rewrite]
^https?:\/\/.+\.pangolin-sdk-toutiao\.com\/api\/ad\/union\/sdk\/(stats|settings)\/.+ _ REJECT-DICT
^https?:\/\/.+\.pangolin-sdk-toutiao\.com\/union\/endcard\/.+\/\?.+ _ REJECT-200
^https?:\/\/.+\.pinduoduo\.com\/marketing_api\/.+\/.+\.(png|jpeg|jpg|mp4) _ REJECT-200
^https?:\/\/googleads\..+\.doubleclick\.net\/mads\/(gma|static\/mad\/sdk\/native).+ _ REJECT-200
^https?:\/\/.+\.googleadservices\.com\/pagead\/.+\?.+ _ REJECT-200
^https?:\/\/.+\.gdt.qq.com\/.+\.fcg\?.+ _ REJECT-200
^https?:\/\/.+\.ugdtimg\.com\/gdt\/0\/.+\.(png|jpeg|jpg|mp4) _ REJECT-200
^https?:\/\/.+\.ugdtimg\.com\/ads_svp_video__.+\.f.+\.(png|jpeg|jpg|mp4)\?.+ _ REJECT-200
[Script]
广告联盟json = type=http-response,script-path=https://raw.githubusercontent.com/T00700/iFreetime/main/adsense.js,pattern=^https:\/\/(api-access\.pangolin-sdk-toutiao\.com\/api\/ad\/union\/sdk\/get_ads|open\.e\.kuaishou\.com\/rest\/e\/v3\/open\/univ$|mi\.gdt\.qq\.com\/gdt_mview\.fcg\?),requires-body=true,enable=true
[MITM]
hostname = %APPEND% *.gdt.qq.com,*.pinduoduo.com,video-dsp.pddpic.com,*.pglstatp-toutiao.com,*.pangolin-sdk-toutiao.com,*.doubleclick.net,*.googleadservices.com,*.ugdtimg.com
