import { HttpClient } from '@angular/common/http';
import { EventEmitter, Injectable } from '@angular/core';
import { environment } from 'src/environments/environment';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  accessToken = '';
  static authEmitter = new EventEmitter<boolean>(); // we only need 1 emitter in app, that is why we made it static


  constructor(private http: HttpClient) { }

  register(body: any){
    return this.http.post(`${environment.api}/register`, body);
  }

  login(body: any){
    return this.http.post(`${environment.api}/login`, body);
  }

  authenticatorLogin(body: any){
    return this.http.post(`${environment.api}/two_factor`, body, {withCredentials: true});
  }

  user(){
    return this.http.get(`${environment.api}/user`);
  }

  refresh(){
    return this.http.post(`${environment.api}/refresh`, {}, {withCredentials: true});
  }

  logout(){
    return this.http.post(`${environment.api}/logout`, {}, {withCredentials: true});
  }
}
