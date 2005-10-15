use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Crypt::OpenSSL::DSA',
    'VERSION_FROM'	=> 'lib/Crypt/OpenSSL/DSA.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    'AUTHOR'            => 'T.J. Mather',
    'LIBS'              => ['-lssl -lcrypto'],
    'DEFINE'            => '-DPERL5',   # perl-5.8/gcc-3.2 needs this
);
