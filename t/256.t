use strict;
use warnings;
use Test::More tests => 68;
use Digest::Shabal qw(shabal_256 shabal_256_hex);

my $len = 0;

while (my $line = <DATA>) {
    chomp $line;
    my ($msg, $digest) = split '\|', $line, 2;
    my $data = pack 'H*', $msg;
    $digest = lc $digest;

    if ($len and not $len % 8) {
        my $md = Digest::Shabal->new(256)->add($data)->hexdigest;
        is($md, $digest, "new/add/hexdigest: $len bits of $msg");
        is(
            shabal_256_hex($data), $digest,
            "shabal_256_hex: $len bits of $msg"
        );
        ok(
            shabal_256($data) eq pack('H*', $digest),
            "shabal_256: $len bits of $msg"
        );
    }

    my $md = Digest::Shabal->new(256)->add_bits($data, $len)->hexdigest;
    is($md, $digest, "new/add_bits/hexdigest: $len bits of $msg");
}
continue { $len++ }

__DATA__
00|AEC750D11FEEE9F16271922FBAF5A9BE142F62019EF8D720F858940070889014
00|EB66AEE3311CA2C6FFD157F56C24C57753269D13D7E09AB56793473007FA519F
C0|9BBC2C62E1E94B672A9B9F29226463E65EDB8F1EACF9156645F532994DB68880
C0|490526E864963980AB22F5335FB517084C4568CF3CD46EA816EDF99595D50B8C
80|22E503D4E288E52B4D09E1411F4C45F5A7FD175372CBD1BA54F105F4CA8AC275
48|279F83D999E563700923B2ECCC902DD484659ED85ED904B2B631A001FB3EE0E5
50|67D22B32029291ADCCDF5AE08FAF23C2F228AECCEDDF0276D8614E40BE00F48C
98|9F9082B5CB6471CE9E807B814687EA2785005BB8107147B36642B9CF601B2FBB
CC|F52E6A62FA8A0E0FCDEA5E12800C3B4301A0BF8B0F897BBE7685CDC659FDD3F8
9800|F4C7DBD9C571B1131F5B4422A54CCCF37A2878A856779F7C8B3AC0020E2AEE0D
9D40|C4C338F93850F39D1E55399A4B7A22F665E6A7885A870F90D98DBD8E1DD75B3B
AA80|B86978918C9C8A0F29EF8F5F35A4EAD7D07AFA289E7AE8FD7FE08DC532BE290B
9830|6645BD8D38A07CBCFC5707AE2AE6A4EC5AE65C1D96BD822B630B92657879971B
5030|220C94AE99A68AD97AC3627867B506E6A4349CABF7AC5FB2C86F445FD75E316F
4D24|292603AE68694BA1BCEA28A97CDF628926E8F7C336A96355F62FA92251308B27
CBDE|D7554321DAF8A324FC414E90CD39187E0D714403A20DB5B28955F3A9725CDC0B
41FB|B956D01ABE2105DAD2C6B29896E14AFBEBD6F0AC750B64E9DCA508A8B94A86E4
4FF400|36D8184592C4FC7209CC920DA84273900A9AF67430E7E0160F5CBDE32B4DDAFD
FD0440|F72BA30F4002A7F933A13C2A1554D4E0EE1337F902C4113B030E46898430838E
424D00|BE1D2E9323316293372D3EF85366E0A0C17ED8001100397B8CBA881579F071B4
3FDEE0|6E92989CDAF4D5A5453324CBBFD5C3411C5AF990B39B8FA042EB7968829585C0
335768|1FF69364898992FD1AD8CCD4E9303211022BE88578EAFC9598A36815A8F3F9C8
051E7C|DCF161BFDB3442CDE37E230ADC646367A266B6EC3F3F314391541ECD06A4EA60
717F8C|C6E7AE2C1AF72CFE8B24521747B17840827956200A91B7B6EDF97D6C46D89D03
1F877C|744AA44A262E0551984E1F476030826E9F70FE7D1F84FD279B60806F965A0D8B
EB35CF80|2375237F84AADCC8B04447D5E0E7C650BD7BD79C8F0A4F9FCD47BA92522635FD
B406C480|B9B671B7301ED457F8323365E0E460E770D64347AB790AF5F4DE2BC4A27876A5
CEE88040|C43F2923762E3331A04AC42318389EF5DC71BFAFACDAF17D6B3B2276CFE8BDC5
C584DB70|5EF1BDE1D568BE037E6D7D306294C0F6AA55B90DABDF30F47BD593635938B12A
53587BC8|5A50DC554B32DC21987CD3BDD6A18BE1E18A84056796F19A2E3CA4F0244E097A
69A305B0|AB2140A0C7AA5AA324956C60CBFBB2D6E44F3E4BC21D11D850D30760F5466E98
C9375ECE|C8BBA9A3B9E9E5A0AFB068ACC0D857596F7E8946352A369DF7398C1B967D0881
C1ECFDFC|AD1CC03AE512D733BB361EFF61793D49D63A184C754EBF7F92A9D2B98EDB3B2F
8D73E8A280|C96A1B588B8BA05C05FB75979D7220E938CEE20A3DAA2B5458E7495CE795C4D2
06F2522080|92B06A4596B7C9C3D1B4E794B0134BB181202BF6F64955E8C4A276BE7FA8CD2B
3EF6C36F20|B0FD9DFF3524A69E5EC7A4F1A045A6E278F194D7596B117C67DD23A693586EA5
0127A1D340|08CF46302250AD44A04E0D0DEECDF1472D9B4A15CE7BEBAF6DFE64398D4120F4
6A6AB6C210|4A60FB8FCF84D69FE30126720AE472E5B7130DB33B3055CE9D49BC5A627ECBA4
AF3175E160|E6ABB8D4BCA6AEDC16AA5C2BBE9CEEA9A789774027E1D19C33AC1CEF476D51AC
B66609ED86|8ED1C464F3BE55A0E7165079528C34F363825ADC2266224AD900AE01089FB9C8
21F134AC57|D735CB59BD420D251953EE01181AAB8F1AB9451F40F1EC698B5BAC89591F3A22
3DC2AADFFC80|A765C10068891FCBD51C8E5BDB40FF0A8FC3C12E8E83305372127F324DB646E8
9202736D2240|5DECB819F3F01FDE9BB7D6180EE65E34325B7343DEB6B34896F378B61A3D0073
F219BD629820|74AECDB04117F84D317ECBDDACA2B455056EDC5A339F62A9D31CEEBC29C370CA
F3511EE2C4B0|496E8484B9232B070C5AA2F7A92B0FDC908109A3956AE140F292B07F278D25A3
3ECAB6BF7720|E69D40F3B36477232B465C2EACEB4415E122AC5B1CC107C3246C1B57B0C3B0B2
CD62F688F498|1F5A1A8340E9D055635A2AAB6F126E8166C3AAE21EABC506626F417803ADF177
C2CBAA33A9F8|4D8015A9B9D22B938E9BB683AE0AE75C4990C93AB39B622F1C1B59C25159C2D5
C6F50BB74E29|6856DF3951FD3273A33316E466EFA9147E54BD0316CE3B546C2552E399477AD5
79F1B4CCC62A00|E095F9B17B008C7D1FE0D48F9631E320D164573932A68F3BD4896C4882DD9FC0
