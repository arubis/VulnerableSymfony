<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use function PHPUnit\Framework\returnArgument;

/**
 * @extends ServiceEntityRepository<User>
 *
 * @method User|null find($id, $lockMode = null, $lockVersion = null)
 * @method User|null findOneBy(array $criteria, array $orderBy = null)
 * @method User[]    findAll()
 * @method User[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function save(User $entity, bool $flush = false): void
    {
        $this->getEntityManager()->persist($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function remove(User $entity, bool $flush = false): void
    {
        $this->getEntityManager()->remove($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function total(): int
    {
        return $this->createQueryBuilder("u")
            ->select("COUNT(u.id)")
            ->getQuery()
            ->getSingleScalarResult();
    }

    /**
     * Used to upgrade (rehash) the user's password automatically over time.
     */
    public function upgradePassword(PasswordAuthenticatedUserInterface $user, string $newHashedPassword): void
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        }

        $user->setPassword($newHashedPassword);

        $this->save($user, true);
    }

    /**
     * Returns the user row matching the given email and pre-hashed password,
     * using a parameterised query to prevent SQL injection (CWE-89 / CWE-798).
     *
     * The caller is responsible for hashing the plain-text password before
     * passing it here, keeping credential logic out of the repository.
     */
    public function getUserLogin(string $email, string $hashedPassword): false|array
    {
        $rawSql = 'SELECT * FROM user WHERE email = :email AND password = :password LIMIT 1';
        $conn = $this->getEntityManager()->getConnection();
        $stmt = $conn->prepare($rawSql);
        return $stmt->executeQuery([
            'email'    => $email,
            'password' => $hashedPassword,
        ])->fetchAssociative();
    }
}
