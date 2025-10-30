// Importation des modules nécessaires depuis NestJS
import { Module } from '@nestjs/common'; 
import { MaisonEditionService } from './maison-edition.service'; // Le service qui contient la logique métier
import { MaisonEditionController } from './maison-edition.controller'; // Le controller qui gère les routes HTTP
import { PrismaService } from 'src/prisma/prisma.service';

@Module({
   // Ici on indique quels sont les "controllers" de ce module
  controllers: [MaisonEditionController],
  // Ici on indique quels sont les "providers" (services, repositories...) de ce module
  providers: [MaisonEditionService, PrismaService], 
})
export class MaisonEditionModule {}
