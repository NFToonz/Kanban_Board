import { JwtPayload, jwtDecode } from 'jwt-decode';

class AuthService {
  getProfile() {
    // TODO: return the decoded token
    const token = this.getToken();
    const decodedToken = jwtDecode<JwtPayload>(token);
    return decodedToken;
    
  }

  loggedIn() {
    // TODO: return a value that indicates if the user is logged in
    const token = this.getToken();
    return token;
  }
  
  isTokenExpired(token: string) {
    // TODO: return a value that indicates if the token is expired
    const decodedToken = jwtDecode<JwtPayload>(token);
    const currentTime = Date.now() / 1000;
    return decodedToken.exp && decodedToken.exp < currentTime;
  }

  getToken(): string {
    // TODO: return the token
    const loggedUser = localStorage.getItem('id_token') || '';
    return loggedUser;
  }

  login(idToken: string) {
    // TODO: set the token to localStorage
    // TODO: redirect to the home page
    localStorage.setItem('id_token', idToken);
    window.location.assign('/');
  }

  logout() {
    // TODO: remove the token from localStorage
    // TODO: redirect to the login page
    localStorage.removeItem('id_token');
    window.location.assign('/login');

  }
}

export default new AuthService();
