<template>
  <div class="hello">
    <h1>{{ msg }}</h1>
    <div>
      <label for="username">Username</label>
      <Input v-model="username" placeholder="Enter name" id="username" style="width: auto"/>
    </div>
    <div>
      <label for="password">Password</label>
      <Input v-model="password" placeholder="Enter password" id="password" style="width: auto"/>
    </div>
    <br>
    <br>
    <Button type="primary" @click="handleLogin" key="login">登录</Button>
    <Button type="primary" @click="handleIsLogin" key="islogin">测试是否登录</Button>
    <Button type="primary" @click="handleTest" key="test">测试index</Button>
  </div>
</template>

<script>
import { doLogin } from '@/api/login'
import request from '@/libs/request'
import axios from 'axios'
export default {
  name: "HelloWorld",
  data() {
    return {
      msg: "Welcome to Your Vue.js App",
      username: "",
      password: ""
    };
  },
  methods: {
    handleLogin() {
      var _this = this;
      var username = _this.username;
      var password = _this.password;
      if (!(username && password)) {
        this.$Modal.error({
          title: "错误",
          content: "用户名和密码不能为空"
        });
        return;
      }
      doLogin(username,password).then(res=>{
        console.log(res)
        if(res.data.status === 200){
          const {token} = res.data;
          this.$Modal.info({
            title: "success",
            content: "登陆成功"
          });
          localStorage.setItem('token', `${token}`)
        }else{
          this.$Modal.error({
            title: "failure",
            content: "登陆失败"
          });
        }
      })
      // var data = {
      //   username: _this.username,
      //   password: _this.password
      // };
      // console.log(data);
      // const _data = new FormData();
      // _data.append("username", _this.username);
      // _data.append("password", _this.password);
      // axios({
      //   method: "post",
      //   url: "http://127.0.0.1:8000/backend/login",
      //   data: _data,
      //   // withCredentials: true
      // }).then(res => {
      //   console.log(res.data);
      //   _this.msg = res.data;
      //   const { token } = res.data;
      //   //localStorage.setItem("sesssionid", sesssionid);
      //   document.cookie = `token=${token}&${username};`
      // });
    },
    handleIsLogin () {
      request({
        method: "get",
        url: "/backend/islogin",
        withCredentials: true
      }).then(res=>{
        console.log(res.data);
        var response = res.data;
        this.$Modal.info({
          title: '是否登陆',
          content: response.tips
        })
      })
    },
    handleTest () {
      request({
        method:'get',
        url: '/backend/index'
      }).then(res=>{
        let response = res.data;
        console.log(response)
        this.$Modal.info({
          title: '/backend/index 路由的数据',
          content: response.tips
        })
      })
    }
  }
};
</script>