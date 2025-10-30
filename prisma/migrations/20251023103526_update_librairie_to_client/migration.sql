/*
  Warnings:

  - You are about to drop the column `librairie_id` on the `Commande` table. All the data in the column will be lost.
  - You are about to drop the `Librairie` table. If the table is not empty, all the data it contains will be lost.

*/
-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "Canal" ADD VALUE 'particulier';
ALTER TYPE "Canal" ADD VALUE 'entreprise';
ALTER TYPE "Canal" ADD VALUE 'distributeur';
ALTER TYPE "Canal" ADD VALUE 'ecole';

-- DropForeignKey
ALTER TABLE "public"."Commande" DROP CONSTRAINT "Commande_librairie_id_fkey";

-- AlterTable
ALTER TABLE "Commande" DROP COLUMN "librairie_id",
ADD COLUMN     "client_id" TEXT;

-- DropTable
DROP TABLE "public"."Librairie";

-- CreateTable
CREATE TABLE "Client" (
    "id" TEXT NOT NULL,
    "nom" TEXT NOT NULL,
    "contact" TEXT,
    "email" TEXT,
    "ifu" INTEGER,
    "telephone" TEXT,
    "adresse" TEXT,
    "type" TEXT NOT NULL DEFAULT 'librairie',
    "remise" DOUBLE PRECISION DEFAULT 0.0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Client_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "Commande" ADD CONSTRAINT "Commande_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "Client"("id") ON DELETE SET NULL ON UPDATE CASCADE;
