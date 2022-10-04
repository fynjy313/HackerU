#### HackerU home work and other
# Занятие 3. Уязвимости OS Command injection
# Домашнее задание
https://hackmd.io/yj70b4GfQ5G6sQE67UmdAQ?view

## Пример 1.

```
<?php
$rootUname = $_GET['rootUname'];
$array = array();
/* check PHP Safe_Mode is off */
if (ini_get('safe_mode')) {
    $array['phpSafeMode'] = '<strong><font class="bad">Fail - php safe mode is on - turn it off before you proceed with the installation</strong></font>br/>';
} else {
    $array['phpSafeMode'] = '<strong><font class="Good">Pass - php safe mode is off</strong></font><br/>';
}
/* Test root account details */
$rootTestCmd1 = 'sudo -S -u ' . $rootUname . ' chmod 0777 /home 2>&1';
exec($rootTestCmd1, $cmdOutput, $err);
$homeDirPerms = substr(sprintf('%o', fileperms('/home')), -4);
if ($homeDirPerms == '0777') {
    $array['rootDetails'] = '<strong><font class="Good">Pass - root account details are good </strong></font><br/>';
} else {
    $array['rootDetails'] = '<strong><font class="bad">The root details provided have not passed: ' . $cmdOutput[0] . '</strong></font><br/>';
}
// reset /home dir permissions
$rootTestCmd2 = 'sudo -S -u ' . $rootUname . ' chmod 0755 /home 2>&1';
exec($rootTestCmd2, $cmdOutput, $err);
echo json_encode($array);
```

### Решение 1:
*(применить к $rootTestCmd1 и $rootTestCmd2)*

```
$rootTestCmd1 = 'sudo -S -u ' . $rootUname . ' chmod 0777 /home 2>&1';
$escaped_command = escapeshellcmd($rootTestCmd1);
exec($escaped_command, $cmdOutput, $err);
```

### Решение 2:
*(применить к $rootTestCmd1 и $rootTestCmd2)*
Вместо exec попробовать использовать chmod:
`chmod($rootUname, 0755);` - Но, в данном случае, команда будет запускаться из под пользователя по умолчанию.

Подробнее:
https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html#php
https://snyk.io/blog/prevent-php-code-injection/
https://www.stackhawk.com/blog/php-command-injection/


## Пример 2.

```
using Microsoft.AspNetCore.Mvc;
using System;
using System.Diagnostics;

namespace WebFox.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OsInjection : ControllerBase
    {
        [HttpGet("{binFile}")]
        public string os(string binFile)
        {
            Process p = new Process();
            p.StartInfo.FileName = binFile; // Noncompliant
            p.StartInfo.RedirectStandardOutput = true;
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            p.Dispose();
            return output;
        }
    }
}
```

### Решение 1:
```
...
Regex rgx = new Regex(@"^[a-zA-Z0-9]+$");
if(rgx.IsMatch(binFile)) {
    Process p = new Process();
    p.StartInfo.FileName = binFile;    
    p.Start();
	...
}
```
https://dotnet-security-guard.github.io/SG0001.htm

## Пример 3.

### Решение:
Переделал метод runMe(cmd, param, res), чтобы в него передавалась команда cmd (захардкожена) и параметры param из риквеста.
В function runMe(cmd, param, res) используется SPAWN вместо EXEC, что позволяет разделять команду и ее аргументы.
Дополнительно можно написать санитайзер (как в решении для #)/
Исправленный код (js не знаю, поэтому мог где то ошибиться в синтаксисе):

```
const express = require('express');
const router = express.Router()
const { exec, spawn }  = require('child_process');

router.post('/ping', (req,res) => {

	runMe('ping', ${req.body.url}, res);	
	
    // exec(`${req.body.url}`, (error) => {
    //     if (error) {
    //         return res.send('error');
    //     }
    //     res.send('pong')
    // })
    
})

router.post('/gzip', (req,res) => {

    runMe('gzip', `${req.query.file_path}`, res);

    // exec(
    //     'gzip ' + req.query.file_path,
    //     function (err, data) {
    //       console.log('err: ', err)
    //       console.log('data: ', data);
    //       res.send('done');
    // });
})

router.get('/run', (req,res) => {

    runMe('run', `${req.params.cmd}`, res);

   // let cmd = req.params.cmd;
   // runMe(cmd,res)
});

function runMe(cmd, param, res){
//    return spawn(cmd, [params]);

    const cmdRunning = spawn(cmd, [param]);
    cmdRunning.on('close', (code) => {
        res.send(`child process exited with code ${code}`);
    });
}

module.exports = router
```

Подробнее:
https://github.com/nodesecurity/eslint-plugin-security/blob/main/docs/avoid-command-injection-node.md
https://peter-chang.medium.com/nodejs-security-issue-javascript-node-example-tutorial-vulnerabilities-hack-line-url-command-injection-412011924d1b


## Пример 4:
```
import testcasesupport.*;
import javax.servlet.http.*;

public class CWE78_OS_Command_Injection__getParameter_Servlet_10 extends AbstractTestCaseServlet
{
    /* uses badsource and badsink */
    public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.staticTrue)
        {
            /* POTENTIAL FLAW: Read data from a querystring using getParameter */
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        String osCommand;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            /* running on Windows */
            osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
        }
        else
        {
            /* running on non-Windows */
            osCommand = "/bin/ls ";
        }

        /* POTENTIAL FLAW: command injection */
        Process process = Runtime.getRuntime().exec(osCommand + data);
        process.waitFor();

    }

    /* goodG2B1() - use goodsource and badsink by changing IO.staticTrue to IO.staticFalse */
    private void goodG2B1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.staticFalse)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        else
        {

            /* FIX: Use a hardcoded string */
            data = "foo";

        }

        String osCommand;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            /* running on Windows */
            osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
        }
        else
        {
            /* running on non-Windows */
            osCommand = "/bin/ls ";
        }

        /* POTENTIAL FLAW: command injection */
        Process process = Runtime.getRuntime().exec(osCommand + data);
        process.waitFor();

    }

    /* goodG2B2() - use goodsource and badsink by reversing statements in if */
    private void goodG2B2(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.staticTrue)
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        String osCommand;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            /* running on Windows */
            osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
        }
        else
        {
            /* running on non-Windows */
            osCommand = "/bin/ls ";
        }

        /* POTENTIAL FLAW: command injection */
        Process process = Runtime.getRuntime().exec(osCommand + data);
        process.waitFor();

    }

    public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        goodG2B1(request, response);
        goodG2B2(request, response);
    }

    /* Below is the main(). It is only used when building this testcase on
     * its own for testing or for building a binary to use in testing binary
     * analysis tools. It is not used when compiling all the testcases as one
     * application, which is how source code analysis tools are tested.
     */
    public static void main(String[] args) throws ClassNotFoundException,
           InstantiationException, IllegalAccessException
    {
        mainFromParent(args);
    }
}
```

### Решение:
Заменяем все куски кода вида
```	
		/* POTENTIAL FLAW: command injection */
		Process process = Runtime.getRuntime().exec(osCommand + data);
        process.waitFor();
```
на
```
        //Safe execute:        
        Process safeProcess = new ProcessBuilder(osCommand, data).start();
        while (true) {
            try {
                safeProcess.exitValue();
                break;
            } catch (Exception e) {
                Thread.sleep(500);
            }
        }
```

Так же, в случае необходимости, если команда заранее неизвестна, необходимо добавить проверку по черному/белому списку. Список потенциально опасных команд: https://gtfobins.github.io/#
