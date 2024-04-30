(function() {var type_impls = {
"svsm":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-BitmapAllocatorTree%3CBitmapAllocator64%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#103-115\">source</a><a href=\"#impl-BitmapAllocatorTree%3CBitmapAllocator64%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"struct\" href=\"svsm/utils/bitmap_allocator/struct.BitmapAllocatorTree.html\" title=\"struct svsm::utils::bitmap_allocator::BitmapAllocatorTree\">BitmapAllocatorTree</a>&lt;<a class=\"struct\" href=\"svsm/utils/bitmap_allocator/struct.BitmapAllocator64.html\" title=\"struct svsm::utils::bitmap_allocator::BitmapAllocator64\">BitmapAllocator64</a>&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#104-109\">source</a><h4 class=\"code-header\">pub const fn <a href=\"svsm/utils/bitmap_allocator/struct.BitmapAllocatorTree.html#tymethod.new\" class=\"fn\">new</a>() -&gt; Self</h4></section></div></details>",0,"svsm::utils::bitmap_allocator::BitmapAllocator1024"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-BitmapAllocatorTree%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#97\">source</a><a href=\"#impl-Clone-for-BitmapAllocatorTree%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html\" title=\"trait svsm::utils::bitmap_allocator::BitmapAllocator\">BitmapAllocator</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"svsm/utils/bitmap_allocator/struct.BitmapAllocatorTree.html\" title=\"struct svsm::utils::bitmap_allocator::BitmapAllocatorTree\">BitmapAllocatorTree</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#97\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.2/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"svsm/utils/bitmap_allocator/struct.BitmapAllocatorTree.html\" title=\"struct svsm::utils::bitmap_allocator::BitmapAllocatorTree\">BitmapAllocatorTree</a>&lt;T&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.77.2/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.77.2/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.2/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.77.2/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","svsm::utils::bitmap_allocator::BitmapAllocator1024"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-BitmapAllocatorTree%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#97\">source</a><a href=\"#impl-Debug-for-BitmapAllocatorTree%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html\" title=\"trait svsm::utils::bitmap_allocator::BitmapAllocator\">BitmapAllocator</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"svsm/utils/bitmap_allocator/struct.BitmapAllocatorTree.html\" title=\"struct svsm::utils::bitmap_allocator::BitmapAllocatorTree\">BitmapAllocatorTree</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#97\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.2/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.77.2/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/1.77.2/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.77.2/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","svsm::utils::bitmap_allocator::BitmapAllocator1024"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Default-for-BitmapAllocatorTree%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#97\">source</a><a href=\"#impl-Default-for-BitmapAllocatorTree%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + <a class=\"trait\" href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html\" title=\"trait svsm::utils::bitmap_allocator::BitmapAllocator\">BitmapAllocator</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/utils/bitmap_allocator/struct.BitmapAllocatorTree.html\" title=\"struct svsm::utils::bitmap_allocator::BitmapAllocatorTree\">BitmapAllocatorTree</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.default\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#97\">source</a><a href=\"#method.default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.2/core/default/trait.Default.html#tymethod.default\" class=\"fn\">default</a>() -&gt; <a class=\"struct\" href=\"svsm/utils/bitmap_allocator/struct.BitmapAllocatorTree.html\" title=\"struct svsm::utils::bitmap_allocator::BitmapAllocatorTree\">BitmapAllocatorTree</a>&lt;T&gt;</h4></section></summary><div class='docblock'>Returns the “default value” for a type. <a href=\"https://doc.rust-lang.org/1.77.2/core/default/trait.Default.html#tymethod.default\">Read more</a></div></details></div></details>","Default","svsm::utils::bitmap_allocator::BitmapAllocator1024"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-BitmapAllocator-for-BitmapAllocatorTree%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#117-184\">source</a><a href=\"#impl-BitmapAllocator-for-BitmapAllocatorTree%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html\" title=\"trait svsm::utils::bitmap_allocator::BitmapAllocator\">BitmapAllocator</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>&gt; <a class=\"trait\" href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html\" title=\"trait svsm::utils::bitmap_allocator::BitmapAllocator\">BitmapAllocator</a> for <a class=\"struct\" href=\"svsm/utils/bitmap_allocator/struct.BitmapAllocatorTree.html\" title=\"struct svsm::utils::bitmap_allocator::BitmapAllocatorTree\">BitmapAllocatorTree</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"associatedconstant.CAPACITY\" class=\"associatedconstant trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#118\">source</a><a href=\"#associatedconstant.CAPACITY\" class=\"anchor\">§</a><h4 class=\"code-header\">const <a href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html#associatedconstant.CAPACITY\" class=\"constant\">CAPACITY</a>: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a> = _</h4></section><section id=\"method.alloc\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#120-122\">source</a><a href=\"#method.alloc\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html#tymethod.alloc\" class=\"fn\">alloc</a>(&amp;mut self, entries: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a>, align: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.77.2/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a>&gt;</h4></section><section id=\"method.free\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#124-126\">source</a><a href=\"#method.free\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html#tymethod.free\" class=\"fn\">free</a>(&amp;mut self, start: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a>, entries: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a>)</h4></section><section id=\"method.set\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#128-152\">source</a><a href=\"#method.set\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html#tymethod.set\" class=\"fn\">set</a>(&amp;mut self, start: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a>, entries: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a>, value: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.bool.html\">bool</a>)</h4></section><section id=\"method.next_free\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#154-165\">source</a><a href=\"#method.next_free\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html#tymethod.next_free\" class=\"fn\">next_free</a>(&amp;self, start: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.77.2/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a>&gt;</h4></section><section id=\"method.get\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#167-171\">source</a><a href=\"#method.get\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html#tymethod.get\" class=\"fn\">get</a>(&amp;self, offset: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.bool.html\">bool</a></h4></section><section id=\"method.empty\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#173-175\">source</a><a href=\"#method.empty\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html#tymethod.empty\" class=\"fn\">empty</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.bool.html\">bool</a></h4></section><section id=\"method.capacity\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#177-179\">source</a><a href=\"#method.capacity\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html#tymethod.capacity\" class=\"fn\">capacity</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a></h4></section><section id=\"method.used\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/utils/bitmap_allocator.rs.html#181-183\">source</a><a href=\"#method.used\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html#tymethod.used\" class=\"fn\">used</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/core/primitive.usize.html\">usize</a></h4></section></div></details>","BitmapAllocator","svsm::utils::bitmap_allocator::BitmapAllocator1024"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()