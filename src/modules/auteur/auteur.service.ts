import { Injectable } from '@nestjs/common';
import { CreateAuteurDto } from './dto/create-auteur.dto';
import { UpdateAuteurDto } from './dto/update-auteur.dto';

@Injectable()
export class AuteurService {
  create(createAuteurDto: CreateAuteurDto) {
    return 'This action adds a new auteur';
  }

  findAll() {
    return `This action returns all auteur`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auteur`;
  }

  update(id: number, updateAuteurDto: UpdateAuteurDto) {
    return `This action updates a #${id} auteur`;
  }

  remove(id: number) {
    return `This action removes a #${id} auteur`;
  }
}
