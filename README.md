<a name="readme-top"></a>

# Powerful x86/x64 Mini Hook-Engine Mirror by Daniel Pistelli Fix include

![hook and unhooked MessageBox](/nthookengine.png)

<details>
  <summary>
    <h2>Table of Contents</h2>
  </summary>
  <ul>
    <li><a href="#why">Why?</a></li>
    <li><a href="#how-to-buildcompile-original-codeHow">How to Build/Compile original code</a></li>
    <li><a href="#code-structure">Code structure</a></li>
    <li><a href="#the-bug-and-fix">The bug and fi</a></li>
  </ul>
</details>

This is not the popular minhook that one is here <https://github.com/TsudaKageyu/minhook>.

On this repository you can find a copy of the code found in <https://www.codeproject.com/Articles/21414/Powerful-x86-x64-Mini-Hook-Engine> and a fix for make it works on windows 10

## Why?

I though was fun to do some necromancy to an old code on the way I found that it doesnt work anymore so I read the code and did some debug to make it works

## How to Build/Compile original code

Visual studio 2022 and its workload Desktop development with C++ are requiere

Open the .sln file with visual studio and let it upgrade the solution. Build the solution as usual. That is, no adictional fix are require

## Code structure

- **nthookengine_original** contain the original code without modifications found on Powerful x86/x64 Mini Hook-Engine
- **nthookengine_modified** code upgrade to vs-studio 2022 with binaries built on this version

## The bug and fix
There is a miss calculation on the code size to disam so I changed it distorm_decode

<p align="right">(<a href="#readme-top">back to top</a>)</p>