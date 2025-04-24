#![no_std]

use core::ptr;

use allocator::{BaseAllocator, ByteAllocator, PageAllocator};

/// Early memory allocator
/// Use it before formal bytes-allocator and pages-allocator can work!
/// This is a double-end memory range:
/// - Alloc bytes forward
/// - Alloc pages backward
///
/// [ bytes-used | avail-area | pages-used ]
/// |            | -->    <-- |            |
/// start       b_pos        p_pos       end
///
/// For bytes area, 'count' records number of allocations.
/// When it goes down to ZERO, free bytes-used area.
/// For pages area, it will never be freed!
///
/// Reference: DeepSeek for const generic and basic knowledge of allocation
pub struct EarlyAllocator<const PAGE_SIZE: usize> {
    start: usize,
    end: usize,
    b: usize,
    p: usize,
    b_cnt: usize,
}

impl<const PAGE_SIZE: usize> EarlyAllocator<PAGE_SIZE> {
	pub const fn new()  -> EarlyAllocator<PAGE_SIZE> {
		EarlyAllocator {
			start: 0,
			end: 0,
			b: 0,
			p: 0,
			b_cnt: 0,
		}
	}
}

impl<const PAGE_SIZE: usize> BaseAllocator for EarlyAllocator<PAGE_SIZE> {
	fn init(&mut self, start: usize, size: usize) {
		self.start = start;
		self.end = start + size;
		self.b = start;
		self.p = self.end;
		self.b_cnt = 0;
	}

	/// Suppose add in bytes-used area
	fn add_memory(&mut self, start: usize, size: usize) -> allocator::AllocResult {
		if start < self.start {
			return Err(allocator::AllocError::NotAllocated);
		}

		if start + size > self.p {
			return Err(allocator::AllocError::MemoryOverlap);
		}
		
		self.b = start + size;
		self.b_cnt += 1;
		Ok(())
	}
}

fn align_up(addr:usize,align:usize) -> usize {
	let mask = align - 1;
	(addr + mask) & !mask
}

fn align_down(addr:usize,align:usize) -> usize {
	let mask = align - 1;
	addr & !mask
}

impl<const PAGE_SIZE: usize> ByteAllocator for EarlyAllocator<PAGE_SIZE> {
	fn alloc(&mut self, layout: core::alloc::Layout) -> allocator::AllocResult<core::ptr::NonNull<u8>> {
		let size = layout.size();
		let align = layout.align();
		let addr = align_up(self.b, align);
		let new_b = addr.checked_add(size).ok_or(allocator::AllocError::NoMemory)?;

		if new_b > self.p {
			return Err(allocator::AllocError::NoMemory)
		}
		
		self.b = new_b;
		self.b_cnt += 1;
		Ok(core::ptr::NonNull::new(addr as *mut u8).unwrap())
	}

	fn dealloc(&mut self, _pos: core::ptr::NonNull<u8>, _layout: core::alloc::Layout) {
		self.b_cnt = self.b_cnt.saturating_sub(1);

		if self.b_cnt == 0 {
			let old_b = self.b;
			let len =  old_b - self.start;
			unsafe {
				core::ptr::write_bytes(self.start as *mut u8, 0, len);
			}

			self.b = self.start;
		}
	}

	fn total_bytes(&self) -> usize {
		let total = self.p - self.start;
		total
	}

	fn used_bytes(&self) -> usize {
		let used = self.b - self.start;
		used
	}

	fn available_bytes(&self) -> usize {
		let avail = self.p - self.b;
		avail
	}
}

impl<const PAGE_SIZE: usize> PageAllocator for EarlyAllocator<PAGE_SIZE> {
	const PAGE_SIZE: usize = PAGE_SIZE;

	fn alloc_pages(&mut self, num_pages: usize, align_pow2: usize) -> allocator::AllocResult<usize> {
		let size = num_pages.checked_mul(PAGE_SIZE).ok_or(allocator::AllocError::NoMemory)?;

		let align = 1 << align_pow2;
		let addr = align_up(self.p, align);
		let new_p = addr.checked_sub(size).ok_or(allocator::AllocError::NoMemory)?;

		if new_p < self.b {
			return Err(allocator::AllocError::NoMemory)
		}
		
		self.p = new_p;
		Ok(new_p)
	}

	fn dealloc_pages(&mut self, _pos: usize, _num_pages: usize) {
		todo!()
	}

	fn total_pages(&self) -> usize {
		let total = (self.p - self.start) / PAGE_SIZE;
		total
	}

	fn used_pages(&self) -> usize {
		let used = (self.b - self.start) / PAGE_SIZE;
		used
	}

	fn available_pages(&self) -> usize {
		let avail = (self.p - self.b) / PAGE_SIZE;
		avail
	}
}
