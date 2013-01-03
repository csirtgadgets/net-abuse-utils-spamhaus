use inc::Module::Install;

name        'Net-Abuse-Utils-Spamhaus';
all_from    'lib/Net/Abuse/Utils/Spamhaus.pm';

requires    'Net::DNS::Resolver'   => '0.72';

WriteAll();
