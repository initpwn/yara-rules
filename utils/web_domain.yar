/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule web_domain {
    meta:
        author = "initpwn"
    strings:
        $s1 = "http://" wide ascii
        $s2 = "https://" wide ascii
    condition:
        any of them
}

