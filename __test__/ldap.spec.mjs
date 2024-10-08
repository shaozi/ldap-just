import test from "ava";
import { readFile } from "node:fs/promises";
import { authenticate } from "../index.js";

test("ldap search user with all attrs including binary", async (t) => {
  let result = await authenticate({
    ldapOpts: {
      url: "ldap://localhost:1389",
    },
    adminDn: "cn=admin,dc=example,dc=com",
    adminPassword: "password",
    username: "einstein",
    userPassword: "password",
    usernameAttribute: "uid",
    userSearchBase: "dc=example,dc=com",
    attributes: ["*"],
  });
  const users = JSON.parse(result);
  t.is(users.dn, "uid=einstein,ou=users,dc=example,dc=com");
  t.is(users.attrs.uid[0], "einstein");
  const b64str = await readFile("./ldifs/einstein.jpg", {
    encoding: "base64",
  });
  t.is(users.bin_attrs.jpegPhoto[0], b64str);
});

test("ldap search user with no attrs", async (t) => {
  let result = await authenticate({
    ldapOpts: {
      url: "ldap://localhost:1389",
    },
    adminDn: "cn=admin,dc=example,dc=com",
    adminPassword: "password",
    username: "einstein",
    userPassword: "password",
    usernameAttribute: "uid",
    userSearchBase: "dc=example,dc=com",
  });
  const users = JSON.parse(result);
  t.deepEqual(users, {
    dn: "uid=einstein,ou=users,dc=example,dc=com",
    attrs: {},
    bin_attrs: {},
  });
});
test("ldap search user with some attrs", async (t) => {
  let result = await authenticate({
    ldapOpts: {
      url: "ldap://localhost:1389",
    },
    adminDn: "cn=admin,dc=example,dc=com",
    adminPassword: "password",
    username: "einstein",
    userPassword: "password",
    usernameAttribute: "uid",
    userSearchBase: "dc=example,dc=com",
    attributes: ["cn", "sn"],
  });
  const users = JSON.parse(result);
  t.deepEqual(users, {
    dn: "uid=einstein,ou=users,dc=example,dc=com",
    attrs: {
      cn: ["Albert Einstein"],
      sn: ["Einstein"],
    },
    bin_attrs: {},
  });
});
test("user loging ldap search user with some attrs", async (t) => {
  let result = await authenticate({
    ldapOpts: {
      url: "ldap://localhost:1389",
    },
    userDn: "uid=einstein,ou=users,dc=example,dc=com",
    userPassword: "password",
    username: "einstein",
    usernameAttribute: "uid",
    userSearchBase: "ou=users,dc=example,dc=com",
    attributes: ["cn", "sn"],
  });
  const users = JSON.parse(result);
  t.deepEqual(users, {
    dn: "uid=einstein,ou=users,dc=example,dc=com",
    attrs: {
      cn: ["Albert Einstein"],
      sn: ["Einstein"],
    },
    bin_attrs: {},
  });
});

test("verify user only", async (t) => {
  let result = await authenticate({
    ldapOpts: {
      url: "ldap://localhost:1389",
    },
    adminDn: "cn=admin,dc=example,dc=com",
    adminPassword: "password",
    username: "einstein",
    usernameAttribute: "uid",
    userSearchBase: "dc=example,dc=com",
    verifyUserExists: true,
  });
  const users = JSON.parse(result);
  t.deepEqual(users, {
    dn: "uid=einstein,ou=users,dc=example,dc=com",
    attrs: {},
    bin_attrs: {},
  });
});
test("Get user with groups", async (t) => {
  let result = await authenticate({
    ldapOpts: {
      url: "ldap://localhost:1389",
    },
    adminDn: "cn=admin,dc=example,dc=com",
    adminPassword: "password",
    username: "einstein",
    userPassword: "password",
    usernameAttribute: "uid",
    userSearchBase: "dc=example,dc=com",
    groupClass: "posixGroup",
    groupsSearchBase: "ou=Groups,dc=example,dc=com",
    groupMemberAttribute: "memberUid",
    groupMemberUserAttribute: "uid",
  });
  const users = JSON.parse(result);
  t.deepEqual(users, {
    dn: "uid=einstein,ou=users,dc=example,dc=com",
    attrs: {
      groups: [
        "cn=员工,ou=Groups,dc=example,dc=com",
        "cn=physics,ou=Groups,dc=example,dc=com",
      ],
      uid: ["einstein"],
    },
    bin_attrs: {},
  });
});
