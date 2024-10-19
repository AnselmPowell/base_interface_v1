'use client';

import { useState, useEffect } from 'react';


export default function UserList() {
  const [users, setUsers] = useState([]);
  const [newUser, setNewUser] = useState({ first_name: '', last_name: '', email: '' });
  const [isLoading, setIsLoading] = useState(false);
  const [createIsLoading, setCreateIsLoading] = useState(false);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    setIsLoading(true);
  
    try {
      const response = await fetch('/api/users');
   
       if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to fetch users');
      }
      const data = await response.json();
      setUsers(data);
    } catch (err) {
      console.error("Error fetching users:", err);
      setUsers([]);
      // Optionally set an error state here to display to the user
    } finally {
      setIsLoading(false);
    }
  };

  const createUser = async () => {
    setCreateIsLoading(true);
    try {
      const response = await fetch('/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newUser),
      });
      if (!response.ok) {
        throw new Error('Failed to create user');
      }
      setNewUser({ first_name: '', last_name: '', email: '' });
      fetchUsers(); // Refetch users after creating a new one
    } catch (err) {
      console.error(err);
    } finally {
      setCreateIsLoading(false);
    }
  };

  const handleInputChange = (e) => {
    setNewUser({ ...newUser, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    createUser();
  };

  return (
    <div>
      <h2>User List</h2>
      {isLoading ? (
        <p>Loading users...</p>
      ) : users.length > 0 ? (
        <ul>
          {users.map((user) => (
            <li key={user.id}>
              {user.first_name} {user.last_name} - {user.email}
            </li>
          ))}
        </ul>
      ) : (
        <>
        <br/>
        <p>User List Pending...</p>
        </>
      )}
      <br/>

      <h3>Add New User</h3>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          name="first_name"
          value={newUser.first_name}
          onChange={handleInputChange}
          placeholder="First Name"
          required
        />
        <input
          type="text"
          name="last_name"
          value={newUser.last_name}
          onChange={handleInputChange}
          placeholder="Last Name"
          required
        />
        <input
          type="email"
          name="email"
          value={newUser.email}
          onChange={handleInputChange}
          placeholder="Email"
          required
        />
        <button type="submit" disabled={createIsLoading}>
          {createIsLoading ? 'Creating...' : 'Add User'}
        </button>
      </form>
    </div>
  );
}