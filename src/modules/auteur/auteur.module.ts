import { Module } from '@nestjs/common';
import { AuteurService } from './auteur.service';
import { AuteurController } from './auteur.controller';

@Module({
  controllers: [AuteurController],
  providers: [AuteurService],
})
export class AuteurModule {}
