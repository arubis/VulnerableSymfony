<?php

/**
 * RED Test – CWE-798 / SQL Injection via String Interpolation
 *
 * This test proves that UserRepository::getUserLogin() embeds user-supplied
 * credentials (email + MD5-hashed password) directly into a raw SQL string
 * using PHP string interpolation, rather than using parameterized / prepared
 * statements.
 *
 * The vulnerability manifests as two distinct problems:
 *  1. Credentials (the WHERE clause values) are hardcoded/inlined into the
 *     query string — CWE-798 / hardcoded credential pattern.
 *  2. No parameterized binding is used, enabling SQL Injection — CWE-89.
 *
 * A SECURE implementation would:
 *  - Use named or positional placeholders  (e.g. "… WHERE email = :email …")
 *  - Pass values via executeQuery(['email' => $email, …])  OR  bindValue()
 *
 * This test FAILS on the current (vulnerable) code because those security
 * properties are ABSENT.  After the fix, the test will PASS.
 *
 * NOTE: Tier-3 (source-analysis) approach is used because the repository
 * requires a live MySQL database plus full Symfony bootstrap to instantiate
 * the repository class at runtime. The test reads the source file, which is
 * the only reliable way to inspect the generated SQL string in this environment.
 */

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

class UserRepositoryHardcodedCredentialsTest extends TestCase
{
    private string $sourceFile;
    private string $sourceCode;

    protected function setUp(): void
    {
        $this->sourceFile = dirname(__DIR__) . '/src/Repository/UserRepository.php';

        self::assertFileExists(
            $this->sourceFile,
            'Source file UserRepository.php must exist for this test.'
        );

        $this->sourceCode = file_get_contents($this->sourceFile);
    }

    // -------------------------------------------------------------------------
    // 1. The query must NOT interpolate variables directly into the SQL string.
    //    A secure query would contain a placeholder (:email, :password, ?, …)
    //    instead of embedding "$email" or "$hashedPassword" in the string.
    // -------------------------------------------------------------------------

    public function testGetUserLoginDoesNotInterpolateEmailIntoRawSql(): void
    {
        self::assertNotRegExp(
            '/"[^"]*\$email[^"]*"/s',
            $this->sourceCode,
            'VULNERABILITY (CWE-798/CWE-89): getUserLogin() interpolates $email ' .
            'directly into the SQL string instead of using a parameterized placeholder. ' .
            'An attacker can inject arbitrary SQL via the email field.'
        );
    }

    public function testGetUserLoginDoesNotInterpolatePasswordIntoRawSql(): void
    {
        self::assertNotRegExp(
            '/"[^"]*\$hashedPassword[^"]*"/s',
            $this->sourceCode,
            'VULNERABILITY (CWE-798/CWE-89): getUserLogin() interpolates $hashedPassword ' .
            'directly into the SQL string. Password values must never be inlined into raw SQL.'
        );
    }

    // -------------------------------------------------------------------------
    // 2. A secure implementation MUST use parameterized / bound parameters.
    //    Assert that executeQuery() is called with at least one bound value.
    // -------------------------------------------------------------------------

    public function testGetUserLoginUsesParameterizedQueryBinding(): void
    {
        // Secure code passes bound values like:
        //   executeQuery($sql, ['email' => $email, 'password' => $hashedPassword])
        //   OR  ->bindValue(':email', $email)
        //   OR  ->bindParam(1, $email)
        $hasParameterizedCall =
            preg_match('/executeQuery\s*\(\s*[^)]*,\s*\[\s*[^\]]+\]/', $this->sourceCode) ||
            preg_match('/bindValue\s*\(/', $this->sourceCode) ||
            preg_match('/bindParam\s*\(/', $this->sourceCode);

        self::assertTrue(
            (bool) $hasParameterizedCall,
            'VULNERABILITY (CWE-798/CWE-89): getUserLogin() does not pass any bound ' .
            'parameters to the database driver. The method calls executeQuery([]) with ' .
            'an empty parameter array, meaning all credential values are inlined into ' .
            'the SQL string rather than being safely bound. A secure implementation must ' .
            'use parameterized query binding.'
        );
    }

    // -------------------------------------------------------------------------
    // 3. The SQL template itself must contain at least one placeholder.
    // -------------------------------------------------------------------------

    public function testGetUserLoginSqlContainsQueryPlaceholder(): void
    {
        // Look for :named or positional ? placeholders inside the rawSql assignment
        $hasPlaceholder =
            preg_match('/\$rawSql\s*=\s*"[^"]*:[a-zA-Z_][a-zA-Z0-9_]*[^"]*"/s', $this->sourceCode) ||
            preg_match('/\$rawSql\s*=\s*"[^"]*\?[^"]*"/s', $this->sourceCode);

        self::assertTrue(
            (bool) $hasPlaceholder,
            'VULNERABILITY (CWE-798): The SQL query in getUserLogin() contains no ' .
            'parameterized placeholders (:email, :password, or ?). This means ' .
            'credential values are hardcoded / interpolated into the query string, ' .
            'which is the exact pattern described in CWE-798 and CWE-89.'
        );
    }
}
