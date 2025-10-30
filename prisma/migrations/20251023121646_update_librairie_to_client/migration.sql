/*
  Warnings:

  - Added the required column `maison_id` to the `Auteur` table without a default value. This is not possible if the table is not empty.
  - Added the required column `maison_id` to the `Client` table without a default value. This is not possible if the table is not empty.
  - Added the required column `maison_id` to the `Commande` table without a default value. This is not possible if the table is not empty.
  - Added the required column `maison_id` to the `Livre` table without a default value. This is not possible if the table is not empty.
  - Added the required column `maison_id` to the `Notification` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Auteur" ADD COLUMN     "maison_id" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "Client" ADD COLUMN     "maison_id" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "Commande" ADD COLUMN     "maison_id" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "Livre" ADD COLUMN     "maison_id" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "Notification" ADD COLUMN     "maison_id" TEXT NOT NULL;

-- CreateTable
CREATE TABLE "MaisonEdition" (
    "id" TEXT NOT NULL,
    "nom" TEXT NOT NULL,
    "email" TEXT,
    "telephone" TEXT,
    "adresse" TEXT,
    "logo" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MaisonEdition_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "Auteur" ADD CONSTRAINT "Auteur_maison_id_fkey" FOREIGN KEY ("maison_id") REFERENCES "MaisonEdition"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Livre" ADD CONSTRAINT "Livre_maison_id_fkey" FOREIGN KEY ("maison_id") REFERENCES "MaisonEdition"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Client" ADD CONSTRAINT "Client_maison_id_fkey" FOREIGN KEY ("maison_id") REFERENCES "MaisonEdition"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Commande" ADD CONSTRAINT "Commande_maison_id_fkey" FOREIGN KEY ("maison_id") REFERENCES "MaisonEdition"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_maison_id_fkey" FOREIGN KEY ("maison_id") REFERENCES "MaisonEdition"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
